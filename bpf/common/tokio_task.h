// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/scratch_mem.h>
#include <common/tokio_task_key.h>
#include <common/tp_info.h>

#include <maps/tokio_task_id_state.h>
#include <maps/tokio_task_state.h>
#include <maps/tokio_thread_state.h>

// Working copies for the copy-modify-publish anchor updates. Per-CPU scratch, not the
// stack: the caller is the server-span-save path, deep in kprobe context, and the two
// structs are ~250 of the 512 stack bytes.
SCRATCH_MEM_TYPED(tokio_task_anchor, tokio_task_state_t)
SCRATCH_MEM_TYPED(tokio_task_id_anchor, tokio_task_id_state_t)
// The resolved snapshot, copied out of the map entry for the caller.
SCRATCH_MEM_TYPED(tokio_parent_snapshot, tp_info_pid_t)

// Incarnation stamp of a Header-keyed entry: the monotonic creation time. Two occupants of
// one Header address cannot share it (the second is created microseconds after the first
// was freed, against a clock tick of nanoseconds), so a child's parent_version recorded at
// spawn stops matching once the address is recycled. Never 0: parent_version == 0 keeps
// meaning "parent not registered at spawn".
static __always_inline u64 tokio_task_incarnation(void) {
    return bpf_ktime_get_ns();
}

// Full-key comparison: two clients can share an ephemeral source port on different
// addresses, and a port-only check would keep a re-anchored task trusted.
static __always_inline u8 tokio_conn_part_equal(const connection_info_part_t *a,
                                                const connection_info_part_t *b) {
    if (a->port != b->port || a->pid != b->pid || a->type != b->type) {
        return 0;
    }
#pragma unroll
    for (u8 i = 0; i < IP_V6_ADDR_LEN_WORDS; ++i) {
        if (a->ip[i] != b->ip[i]) {
            return 0;
        }
    }
    return 1;
}

// Copies an anchor's snapshot into per-CPU scratch before it is returned. A preallocated LRU
// element freed by a concurrent re-anchor goes back to the free list with no grace period
// (htab_lru_map_update_elem), so a pointer into it could be rewritten under the reader: the
// anchor epoch is re-read after the copy, and a change discards it (a re-anchor bumps it, a
// reused element carries another task's). The consumer's in-place writes land on the copy.
static __always_inline tp_info_pid_t *tokio_snapshot_out(const tp_info_pid_t *tp,
                                                         const u64 *anchor_epoch) {
    const u64 epoch_before = *(volatile const u64 *)anchor_epoch;
    tp_info_pid_t *snapshot = (tp_info_pid_t *)tokio_parent_snapshot_mem();
    if (!snapshot) {
        return NULL;
    }
    *snapshot = *tp;
    if (*(volatile const u64 *)anchor_epoch != epoch_before) {
        return NULL;
    }
    return snapshot;
}

// Walks the Header-keyed parent chain from task_id to the task anchored to an inbound
// request and returns its trace snapshot, or NULL. Every hop is validated: the entry must
// exist, its anchor_epoch must equal the epoch the child recorded at spawn (a parent
// re-anchored to a later request fails closed), and a parent link is followed only while
// the parent's incarnation stamp still matches (a recycled Header fails closed). Shared
// anchors (conn_shared) are skipped. The snapshot is the only source: server_traces_aux is
// last-write-wins per connection key, so a late egress could read the next request's
// trace there. tp_valid is set with conn_valid and cleared only together with conn_shared
// or conn_valid, so an anchor always carries a snapshot.
//
// egress selects the debug lines; the poll-entry refresh walks the same chain silently.
static __always_inline tp_info_pid_t *
find_tokio_parent_trace(u32 tgid, u64 task_id, const u8 egress) {
    enum { k_max_tokio_task_depth = 8 };
    u8 check_epoch = 0;
    u64 expected_epoch = 0;
    for (u8 i = 0; i < k_max_tokio_task_depth; ++i) {
        if (!task_id) {
            if (egress) {
                bpf_dbg_printk("tokio walk END null-task i=%d", i);
            }
            return NULL;
        }

        const tokio_task_key_t key = tokio_task_key(tgid, task_id);
        tokio_task_state_t *task_state =
            (tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &key);
        if (!task_state) {
            // Never registered, or LRU-evicted.
            if (egress) {
                bpf_dbg_printk("tokio walk END no-state i=%d task=%llx", i, task_id);
            }
            return NULL;
        }

        if (check_epoch && task_state->anchor_epoch != expected_epoch) {
            if (egress) {
                bpf_dbg_printk(
                    "tokio walk END stale-epoch task=%llx exp=%d", task_id, (u32)expected_epoch);
            }
            return NULL;
        }

        if (task_state->conn_valid && !task_state->conn_shared && task_state->tp_valid) {
            if (egress) {
                bpf_dbg_printk("tokio walk RESOLVE-SNAP task=%llx", task_id);
            }
            // The incarnation stamp is re-read too: a reused element could carry another
            // task's epoch at the same value.
            const u64 version = *(volatile const u64 *)&task_state->version;
            tp_info_pid_t *snapshot =
                tokio_snapshot_out(&task_state->tp, &task_state->anchor_epoch);
            if (*(volatile const u64 *)&task_state->version != version) {
                return NULL;
            }
            return snapshot;
        }

        // No parent, or a self link left by pointer reuse.
        if (!task_state->parent || task_state->parent == task_id) {
            if (egress) {
                bpf_dbg_printk("tokio walk END no/self-parent task=%llx", task_id);
            }
            return NULL;
        }

        const tokio_task_key_t parent_key = tokio_task_key(tgid, task_state->parent);
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &parent_key);
        if (!parent_state) {
            if (egress) {
                bpf_dbg_printk("tokio walk END parent-gone parent=%llx", task_state->parent);
            }
            return NULL;
        }
        // parent_version == 0: the parent was not registered when this child was spawned,
        // so the link cannot be verified and is not followed.
        if (!task_state->parent_version || parent_state->version != task_state->parent_version) {
            if (egress) {
                bpf_dbg_printk("tokio walk END stale-parent pv=%llu cur=%llu",
                               task_state->parent_version,
                               parent_state->version);
            }
            return NULL;
        }
        check_epoch = 1;
        expected_epoch = task_state->parent_epoch;
        task_id = task_state->parent;
    }
    if (egress) {
        bpf_dbg_printk("tokio walk END max-depth");
    }
    return NULL;
}

// Id-keyed twin of find_tokio_parent_trace, the debug-build path: the id map is populated
// only where tokio's TLS setter and Id::next fire, and release leaves it empty. Task ids
// are never reused, so in place of the incarnation stamp the walk requires parent_id < id.
static __always_inline tp_info_pid_t *
find_tokio_parent_trace_by_id(u32 tgid, u64 task_id, const u8 egress) {
    enum { k_max_tokio_id_depth = 8 };
    u8 check_epoch = 0;
    u64 expected_epoch = 0;
    for (u8 i = 0; i < k_max_tokio_id_depth; ++i) {
        if (!task_id) {
            return NULL;
        }

        const tokio_task_key_t key = tokio_task_key(tgid, task_id);
        tokio_task_id_state_t *state =
            (tokio_task_id_state_t *)bpf_map_lookup_elem(&tokio_task_id_state, &key);
        if (!state) {
            // Never seen born, evicted, or deleted at dealloc: the deletion is what fails a
            // reused pooled driver closed instead of resolving its first request.
            if (egress) {
                bpf_dbg_printk("tokio idwalk END no-state i=%d id=%llu", i, task_id);
            }
            return NULL;
        }

        if (check_epoch && state->anchor_epoch != expected_epoch) {
            if (egress) {
                bpf_dbg_printk(
                    "tokio idwalk END stale-epoch id=%llu exp=%llu", task_id, expected_epoch);
            }
            return NULL;
        }

        if (state->conn_valid && !state->conn_shared && state->tp_valid) {
            if (egress) {
                bpf_dbg_printk("tokio idwalk RESOLVE-SNAP id=%llu", task_id);
            }
            return tokio_snapshot_out(&state->tp, &state->anchor_epoch);
        }

        // A parent is always created before its child: anything else is root or corruption.
        if (!state->parent_id || state->parent_id >= task_id) {
            if (egress) {
                bpf_dbg_printk("tokio idwalk END root/invalid parent_id=%llu", state->parent_id);
            }
            return NULL;
        }
        check_epoch = 1;
        expected_epoch = state->parent_epoch;
        task_id = state->parent_id;
    }
    if (egress) {
        bpf_dbg_printk("tokio idwalk END max-depth");
    }
    return NULL;
}

// Anchors the inbound request on the task running right now, at server-span save: the one
// moment "this thread runs this request's task" is verifiably true on a work-stealing
// runtime. Driven from the generic server_or_client_trace() path; a no-op for threads that
// never polled a Tokio task. tp is the server trace just saved, never NULL.
//
// The id-keyed entry is anchored when current_id is set (the setter fired within this poll:
// debug builds) and the Header-keyed task is then left alone, since in debug it is a
// per-worker root shared by every request on the worker. Otherwise the Header-keyed task
// is anchored, created on the spot when OBI never saw its Cell::new (a connection task
// older than OBI's attachment).
//
// A task re-anchored to a different connection key is a shared, long-lived task: it is
// marked conn_shared and never resolved from again. Every anchor bumps anchor_epoch, so
// lineage recorded under an earlier request stops resolving through it.
//
// Writes are copy-modify-publish: another CPU may be walking the entry, and an in-place
// multi-word write of the ~100-byte snapshot could be read torn under tp_valid = 1.
// bpf_map_update_elem gives later lookups a complete element; a reader that already holds
// the old one copies the snapshot out and re-checks the epoch (tokio_snapshot_out), since a
// preallocated element returns to the free list with no grace period.
static __always_inline void
tokio_tag_inbound_conn(u64 id, const connection_info_part_t *conn_part, const tp_info_pid_t *tp) {
    const tokio_thread_state_t *ts =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!ts || !ts->current_task) {
        return;
    }

    if (ts->current_id) {
        const tokio_task_key_t id_key = tokio_task_key(ts->tgid, ts->current_id);
        const tokio_task_id_state_t *id_state =
            (const tokio_task_id_state_t *)bpf_map_lookup_elem(&tokio_task_id_state, &id_key);
        tokio_task_id_state_t *updated = (tokio_task_id_state_t *)tokio_task_id_anchor_mem();
        if (!updated) {
            return;
        }
        if (id_state) {
            *updated = *id_state;
        } else {
            // Id::next not seen: a task older than OBI's attachment.
            *updated = (tokio_task_id_state_t){0};
        }
        if (updated->conn_valid && !tokio_conn_part_equal(&updated->conn, conn_part)) {
            updated->conn_shared = 1;
            updated->tp_valid = 0; // an ambiguous task must not keep a trusted snapshot
        }
        if (!updated->conn_shared) {
            updated->conn = *conn_part;
            updated->conn_valid = 1;
            updated->tp = *tp;
            updated->tp_valid = 1;
        }
        updated->anchor_epoch++;
        bpf_map_update_elem(&tokio_task_id_state, &id_key, updated, BPF_ANY);
        // Read by the integration suite (assertTokioTrustWindow): keep the text in sync.
        bpf_dbg_printk("tokio handler id conn SET: id=%llu port=%d epoch=%llu",
                       ts->current_id,
                       conn_part->port,
                       updated->anchor_epoch);
        return;
    }

    const tokio_task_key_t task_key = tokio_task_key(ts->tgid, ts->current_task);
    const tokio_task_state_t *task_state =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_key);

    tokio_task_state_t *updated = (tokio_task_state_t *)tokio_task_anchor_mem();
    if (!updated) {
        return;
    }
    if (task_state) {
        *updated = *task_state;
    } else {
        *updated = (tokio_task_state_t){.version = tokio_task_incarnation()};
    }

    if (updated->conn_valid && !tokio_conn_part_equal(&updated->conn, conn_part)) {
        updated->conn_shared = 1;
        updated->tp_valid = 0; // an ambiguous task must not keep a trusted snapshot
    }
    if (!updated->conn_shared) {
        updated->conn = *conn_part;
        updated->conn_valid = 1;
        updated->tp = *tp;
        updated->tp_valid = 1;
    }
    // Bumped for a shared task too, so nothing keeps resolving through it.
    updated->anchor_epoch++;
    bpf_map_update_elem(&tokio_task_state, &task_key, updated, BPF_ANY);
    // Read by the integration suite (assertTokioTrustWindow): keep the text in sync.
    bpf_dbg_printk("tokio handler task conn SET: task=%llx port=%d epoch=%llu",
                   ts->current_task,
                   conn_part->port,
                   updated->anchor_epoch);
}

// Closes the anchor's trust window at the response (the HTTP/1 response path and
// delete_server_trace). An anchor is valid strictly from its span save to its response, not
// until the next save: a missed save would otherwise leave the previous request's snapshot
// and epoch on the task for the next request's children to resolve. The epoch bump makes
// links recorded during the finished request stop matching.
//
// Cleared in place, unlike the anchor: each store is one word and any interleaving a
// reader can observe only moves it toward failing closed (conn_valid first, so a reader
// mid-clear resolves nothing), and it keeps the struct copies off this kprobe stack.
static __always_inline void tokio_untag_inbound_conn(u64 id) {
    const tokio_thread_state_t *ts =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!ts) {
        return;
    }

    if (ts->current_id) {
        const tokio_task_key_t id_key = tokio_task_key(ts->tgid, ts->current_id);
        tokio_task_id_state_t *id_state =
            (tokio_task_id_state_t *)bpf_map_lookup_elem(&tokio_task_id_state, &id_key);
        if (id_state && id_state->conn_valid) {
            id_state->conn_valid = 0;
            id_state->tp_valid = 0;
            id_state->anchor_epoch++;
            // Read by the integration suite (assertTokioTrustWindow): keep the text in sync.
            bpf_dbg_printk("tokio handler id conn CLEAR: id=%llu epoch=%llu",
                           ts->current_id,
                           id_state->anchor_epoch);
        }
        // The Header-derived task is never anchored while the id path is active.
        return;
    }

    if (ts->current_task) {
        const tokio_task_key_t task_key = tokio_task_key(ts->tgid, ts->current_task);
        tokio_task_state_t *task_state =
            (tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_key);
        if (task_state && task_state->conn_valid) {
            task_state->conn_valid = 0;
            task_state->tp_valid = 0;
            task_state->anchor_epoch++;
            // Read by the integration suite (assertTokioTrustWindow): keep the text in sync.
            bpf_dbg_printk("tokio handler task conn CLEAR: task=%llx epoch=%llu",
                           ts->current_task,
                           task_state->anchor_epoch);
        }
    }
}
