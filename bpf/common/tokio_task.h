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
