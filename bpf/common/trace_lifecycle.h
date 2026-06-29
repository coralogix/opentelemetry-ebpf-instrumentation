// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "common/lw_thread.h"
#include <bpfcore/utils.h>

#include <common/event_defs.h>
#include <common/runtime.h>
#include <common/trace_key.h>
#include <common/tracing.h>

#include <maps/cp_support_connect_info.h>
#include <maps/incoming_trace_map.h>
#include <maps/java_vt_threads.h>
#include <maps/outgoing_trace_map.h>
#include <maps/server_traces.h>
#include <maps/tokio_task_state.h>
#include <maps/tokio_thread_state.h>

#include <gotracer/go_common.h>

#include <shared/obi_ctx.h>

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn,
                                                trace_key_t *t_key) {
    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_SERVER);
    int res = bpf_map_delete_elem(&server_traces, t_key);
    bpf_dbg_printk("Deleting server span for id=%llx, pid=%d, ns=%x",
                   bpf_get_current_pid_tgid(),
                   t_key->p_key.pid,
                   t_key->p_key.ns);
    bpf_dbg_printk("Deleting server span for res=%d", res);
    if (!(t_key->p_key.tid & JAVA_VT_TID_FLAG)) {
        obi_ctx__del(bpf_get_current_pid_tgid());
    }
}

static __always_inline void delete_client_trace_info(pid_connection_info_t *pid_conn) {
    bpf_dbg_printk("Deleting client trace map for connection, pid=%d", pid_conn->pid);
    dbg_print_http_connection_info(&pid_conn->conn);

    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_CLIENT);

    egress_key_t e_key = {
        .d_port = pid_conn->conn.d_port,
        .s_port = pid_conn->conn.s_port,
    };
    sort_egress_key(&e_key);
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
    bpf_map_delete_elem(&cp_support_connect_info, pid_conn);
}

static __always_inline u8 find_trace_for_server_request(connection_info_t *conn,
                                                        tp_info_t *tp,
                                                        const u8 type) {
    u8 found_tp = 0;
    connection_info_t sorted_conn = *conn;
    sort_connection_info(&sorted_conn);
    tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, &sorted_conn);
    if (existing_tp) {
        found_tp = 1;
        bpf_dbg_printk("Found incoming (TCP/IP) tp for server request");
        __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
        bpf_map_delete_elem(&incoming_trace_map, &sorted_conn);
    } else {
        bpf_dbg_printk("Looking up tracemap for");
        dbg_print_http_connection_info(conn);

        existing_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

        bpf_dbg_printk("existing_tp=%llx", existing_tp);

        if (!disable_black_box_cp && correlated_requests(tp, existing_tp)) {
            if (existing_tp->valid) {
                bpf_dbg_printk("Found existing correlated tp for server request");
                // Mark the client info as invalid (used), in case the client
                // request information is not cleaned up.
                if ((type == EVENT_HTTP_REQUEST && existing_tp->req_type == EVENT_HTTP_CLIENT) ||
                    (type == EVENT_TCP_REQUEST && existing_tp->req_type == EVENT_TCP_REQUEST)) {
                    found_tp = 1;
                    __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
                    __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
                    // We ensure that server requests match the client type, otherwise SSL
                    // can often be confused with TCP.
                    existing_tp->valid = 0;
                    set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, existing_tp);
                    bpf_dbg_printk("setting the client info as used");
                } else {
                    bpf_dbg_printk("incompatible trace info, not using the correlated tp, type=%d, "
                                   "other type=%d",
                                   type,
                                   existing_tp->req_type);
                }
            } else {
                bpf_dbg_printk("the existing client tp was already used, ignoring");
            }
        }
    }

    return found_tp;
}

static __always_inline void server_or_client_trace(const u8 type,
                                                   connection_info_t *conn,
                                                   lw_thread_t lw_thread,
                                                   tp_info_pid_t *tp_p,
                                                   u8 ssl,
                                                   const u16 orig_dport,
                                                   u32 stream_id,
                                                   u64 map_update_flags) {

    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);

    if (type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        // Key the server trace by the mounted virtual thread's logical id,
        // if any: concurrent requests whose VTs read on the same carrier tid
        // would otherwise collide in the conflict branch below.
        const u8 vt_keyed = java_vt_translate_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        connection_info_part_t conn_part = {};
        populate_ephemeral_info(&conn_part, conn, orig_dport, host_pid, FD_SERVER);

        bpf_dbg_printk("Saving connection server span for pid=%d, tid=%d, ephemeral_port=%d",
                       t_key.p_key.pid,
                       t_key.p_key.tid,
                       conn_part.port);
        bpf_dbg_printk("server_traces_aux WRITE: ip_hi=%llx ip_lo=%llx port=%d pid=%d",
                       *(const u64 *)(&conn_part.addr[0]),
                       *(const u64 *)(&conn_part.addr[8]),
                       conn_part.port,
                       conn_part.pid);

        bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

        // Only touch the Tokio-specific maps when this thread has actually
        // polled a Tokio task (tokio_thread_state is set) — i.e. this is a Tokio
        // process.  Non-Tokio servers (Go, Java, Python, nginx, …) reach this path
        // on every HTTP request and must not pay for these writes / LRU churn.
        const tokio_thread_state_t *ts =
            (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
        if (ts && ts->current_task) {
            // Record inbound conn for Tokio ancestry-walk fallbacks.  This fires on
            // the handler thread even when accept4 happened on a different thread
            // (e.g., actix-web's tokio-rt-worker), so poll-refresh alone can't set it.
            bpf_map_update_elem(&tokio_thread_inbound_conn, &id, &conn_part, BPF_ANY);
            // Process-level record: enables the last-resort fallback for tasks on
            // tokio blocking-pool threads (spawn_blocking), which run on a different
            // OS thread than the handler, making both ancestry walk and thread-level
            // fallback fail.
            const u32 tgid = (u32)(id >> 32);
            bpf_map_update_elem(&tokio_process_inbound_conn, &tgid, &conn_part, BPF_ANY);
            bpf_dbg_printk(
                "tokio process inbound conn WRITE: tgid=%d port=%d", tgid, conn_part.port);
            // Fix 1: mark the currently-running handler task conn_valid so that any
            // descendant that reaches it via the ancestry walk (including spawn_blocking
            // tasks if registered in tokio_task_state) finds conn_valid=1 directly.
            //
            // Lazy-registration extension: if the task is NOT yet in tokio_task_state
            // (pre-OBI handler — created before OBI attached, never seen by
            // obi_uprobe_tokio_task_new), CREATE the entry here.  This ensures that
            // the spawn_blocking uretprobe's Try-1 lookup succeeds for these tasks
            // instead of falling through to racy thread- or process-level fallbacks.
            tokio_task_state_t *task_state =
                (tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &ts->current_task);
            if (task_state) {
                task_state->conn = conn_part;
                task_state->conn_valid = 1;
                bpf_dbg_printk("tokio handler task conn_valid SET: task=%llx port=%d",
                               ts->current_task,
                               conn_part.port);
            } else {
                tokio_task_state_t new_state = {};
                new_state.conn = conn_part;
                new_state.conn_valid = 1;
                new_state.version = 1;
                bpf_map_update_elem(&tokio_task_state, &ts->current_task, &new_state, BPF_ANY);
                bpf_dbg_printk("tokio handler task LAZY REG: task=%llx port=%d",
                               ts->current_task,
                               conn_part.port);
            }
        }

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        if (existing && (existing->req_type == tp_p->req_type) &&
            (tp_p->req_type == EVENT_HTTP_REQUEST)) {
            existing->valid = 0;
            bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
            return;
        }

        bpf_dbg_printk(
            "Saving thread server span for ns=%x, extra_id=%llx", t_key.p_key.ns, t_key.extra_id);
        bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);
        // traces_ctx_v1 stays keyed by the raw pid_tgid (external surface):
        // skip it for VT-handled requests, where a carrier-keyed entry would
        // attribute this context to whatever runs on the carrier next.
        if (!vt_keyed) {
            obi_ctx__set(id, &tp_p->tp);
        }

        // If we have lightweight passed on (e.g. goroutine), store the traceparent information on it
        if (lw_thread != k_lw_thread_none) {
            bpf_d_printk("saving tp for lightweight thread=%llx", lw_thread);

            go_addr_key_t g_key = {};
            go_addr_key_from_id_and_pid(&g_key, (void *)lw_thread, host_pid);

            bpf_map_update_elem(&go_trace_map, &g_key, &tp_p->tp, BPF_ANY);
        }
    } else {
        // Setup a pid, so that we can find it in TC.
        // We need the PID id to be able to query ongoing_http and update
        // the span id with the SEQ/ACK pair.
        tp_p->pid = host_pid;
        egress_key_t e_key = {
            .d_port = conn->d_port,
            .s_port = conn->s_port,
            .stream_id = stream_id,
        };
        sort_egress_key(&e_key);

        if (ssl) {
            // Clone and mark it invalid for the purpose of storing it in the
            // outgoing_trace_map, if it's an SSL connection
            tp_info_pid_t tp_p_invalid = {0};
            __builtin_memcpy(&tp_p_invalid, tp_p, sizeof(tp_p_invalid));
            tp_p_invalid.valid = 0;
            bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, map_update_flags);
        } else {
            bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, map_update_flags);
            if (!java_vt_mounted()) {
                obi_ctx__set(id, &tp_p->tp);
            }
        }
    }
}
