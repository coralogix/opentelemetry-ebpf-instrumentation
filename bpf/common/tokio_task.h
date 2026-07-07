// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

#include <maps/server_traces.h>
#include <maps/tokio_task_state.h>
#include <maps/tokio_thread_state.h>

static __always_inline tp_info_pid_t *find_tokio_parent_trace(u64 task_id) {
    enum { k_max_tokio_task_depth = 8 };
    for (u8 i = 0; i < k_max_tokio_task_depth; ++i) {
        if (!task_id) {
            return NULL;
        }

        const tokio_task_state_t *task_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_id);
        if (!task_state) {
            // obi has no record of it in the tokio_task_state map because either never seen
            // by task_new/poll or its entry was evicted by the map LRU.
            return NULL;
        }

        if (task_state->conn_valid) {
            bpf_dbg_printk("find_tokio: task=%llx conn_valid=1, looking up server_traces_aux",
                           task_id);
            bpf_dbg_printk("find_tokio: READ key ip_hi=%llx ip_lo=%llx port=%d pid=%d",
                           *(const u64 *)(&task_state->conn.addr[0]),
                           *(const u64 *)(&task_state->conn.addr[8]),
                           task_state->conn.port,
                           task_state->conn.pid);
            tp_info_pid_t *tp = bpf_map_lookup_elem(&server_traces_aux, &task_state->conn);
            bpf_dbg_printk("find_tokio: server_traces_aux result=%p", tp);
            if (tp) {
                return tp;
            }
        }

        // Stop if there is no parent, or if the parent points back at this task
        // (a self-referential link from pointer reuse), never follow it.
        if (!task_state->parent || task_state->parent == task_id) {
            return NULL;
        }

        // We need to verify that the parent pointer still refers to the same task recorded at
        // spawn time. Under LRU eviction a parent Header pointer can be reused by an unrelated task;
        // following it would resolve a wrong server trace. Only a positive mismatch
        // aborts: if parent_version was never captured (0), the
        // link is trusted to avoid false-aborting a real but unversioned lineage.
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_state->parent);
        if (!parent_state) {
            return NULL;
        }
        if (task_state->parent_version && parent_state->version != task_state->parent_version) {
            bpf_dbg_printk("find_tokio: stale parent task=%llx parent=%llx (version mismatch)",
                           task_id,
                           task_state->parent);
            return NULL;
        }
        task_id = task_state->parent;
    }
    return NULL;
}

// WRITE counterpart to find_tokio_parent_trace(): anchors the inbound server
// connection on the Tokio side at server-span-save time, so that descendant
// spawned tasks resolve the owning server trace via the ancestry walk.  Called
// from the generic server_or_client_trace() path (EVENT_HTTP_REQUEST).
//
// Unlike asyncio — which anchors conn at task-init time via pid_tid_to_conn on
// the accepting thread — Tokio's work-stealing, spawn_blocking, and cross-thread
// accept (actix-web) mean the spawning thread may not hold the inbound conn.
// The server-span-save event is Tokio's only reliable "this thread owns this
// request right now" anchor, which is why this is driven from the generic path
// rather than a Tokio-specific probe.
//
// No-op unless the calling thread has actually polled a Tokio task
// (tokio_thread_state is set): non-Tokio servers (Go, Java, Python, nginx, …)
// reach the server-span path on every request and must not pay for these
// writes / LRU churn.
static __always_inline void tokio_tag_inbound_conn(u64 id,
                                                   const connection_info_part_t *conn_part) {
    const tokio_thread_state_t *ts =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!ts || !ts->current_task) {
        return;
    }

    // Record inbound conn for Tokio ancestry-walk fallbacks.  This fires on the
    // handler thread even when accept4 happened on a different thread (e.g.,
    // actix-web's tokio-rt-worker), so poll-refresh alone can't set it.
    bpf_map_update_elem(&tokio_thread_inbound_conn, &id, conn_part, BPF_ANY);

    // Process-level record: enables the last-resort fallback for tasks on tokio
    // blocking-pool threads (spawn_blocking), which run on a different OS thread
    // than the handler, making both ancestry walk and thread-level fallback fail.
    const u32 tgid = (u32)(id >> 32);
    bpf_map_update_elem(&tokio_process_inbound_conn, &tgid, conn_part, BPF_ANY);
    bpf_dbg_printk("tokio process inbound conn WRITE: tgid=%d port=%d", tgid, conn_part->port);

    // Mark the currently-running handler task conn_valid so that any descendant
    // that reaches it via the ancestry walk (including spawn_blocking tasks if
    // registered in tokio_task_state) finds conn_valid=1 directly.
    //
    // Lazy-registration extension: if the task is NOT yet in tokio_task_state
    // (pre-OBI handler — created before OBI attached, never seen by
    // obi_uretprobe_tokio_cell_new), CREATE the entry here.  This ensures the
    // spawn_blocking uretprobe's Try-1 lookup succeeds for these tasks instead
    // of falling through to racy thread- or process-level fallbacks.
    tokio_task_state_t *task_state =
        (tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &ts->current_task);
    if (task_state) {
        task_state->conn = *conn_part;
        task_state->conn_valid = 1;
        bpf_dbg_printk("tokio handler task conn_valid SET: task=%llx port=%d",
                       ts->current_task,
                       conn_part->port);
    } else {
        tokio_task_state_t new_state = {};
        new_state.conn = *conn_part;
        new_state.conn_valid = 1;
        new_state.version = 1;
        bpf_map_update_elem(&tokio_task_state, &ts->current_task, &new_state, BPF_ANY);
        bpf_dbg_printk(
            "tokio handler task LAZY REG: task=%llx port=%d", ts->current_task, conn_part->port);
    }
}
