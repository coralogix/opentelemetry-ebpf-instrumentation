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

// Anchor updates are copy-modify-publish (tokio_tag_inbound_conn). The working copies live
// in per-CPU scratch instead of on the stack: the call site is the server-span-save path,
// deep in kprobe context, and the two structs together are ~250 bytes of the 512-byte BPF
// stack.
SCRATCH_MEM_TYPED(tokio_task_anchor, tokio_task_state_t)
SCRATCH_MEM_TYPED(tokio_task_id_anchor, tokio_task_id_state_t)

// Incarnation stamp of a Header-keyed task entry: the monotonic creation time
// (bpf_ktime_get_ns). Two occupants of one Header address can never share it: the second
// is created only after the first was freed, and that path (raw::dealloc, the allocator,
// Cell::new, two uprobe traps) is microseconds long against a clock tick of a few tens of
// nanoseconds at worst. A child records its parent's stamp at spawn (parent_version) and
// the walk follows the link only while it still matches, so a stale link to a recycled
// address fails closed even though raw::dealloc deleted the previous occupant's entry (a
// counter restarting at 1 for the new occupant would have matched the child's stamp of the
// old one). CLOCK_MONOTONIC never repeats or goes backwards; it is never 0, so
// parent_version == 0 keeps meaning "parent not registered at spawn".
static __always_inline u64 tokio_task_incarnation(void) {
    return bpf_ktime_get_ns();
}

// Full-key equality for the inbound-connection anchor. Comparing only the port is not
// enough to detect a task being re-anchored across requests: two different clients can
// coincidentally use the same ephemeral source port (different addresses, e.g. behind
// NAT), and a port-only check would then silently overwrite the anchor last-write-wins
// while keeping it trusted — a cross-request misattribution path. Compare every field
// that participates in the server_traces_aux key.
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

static __always_inline tp_info_pid_t *
find_tokio_parent_trace(u32 tgid, u64 task_id, const u8 egress) {
    // egress is set only for the traceparent-injection walk at the outgoing request; the
    // far more frequent poll-entry obi_ctx refresh walks pass 0 and stay silent, so they
    // do not flood the debug ringbuf and evict the egress lines.
    enum { k_max_tokio_task_depth = 8 };
    // Anchor-epoch expectation carried across hops (mirror of the id walk): when we follow
    // a child->parent link we require the parent to still be in the anchor epoch the child
    // recorded at spawn. A mismatch means the parent conn task has been re-anchored to a
    // later request since this lineage was created (a pooled driver / worker task that
    // outlived its request) — resolving through it would attribute this egress to whatever
    // request the anchor serves now. Fail closed. The leaf carries no expectation.
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
            // obi has no record of it in the tokio_task_state map because either never seen
            // by task_new/poll or its entry was evicted by the map LRU.
            if (egress) {
                bpf_dbg_printk("tokio walk END no-state i=%d task=%llx", i, task_id);
            }
            return NULL;
        }

        // The anchor we are about to trust must be in the epoch this lineage was created
        // under (see the loop preamble). A re-anchored keep-alive conn task (pooled
        // driver / worker parent) fails closed here instead of resolving a later request.
        if (check_epoch && task_state->anchor_epoch != expected_epoch) {
            if (egress) {
                bpf_dbg_printk(
                    "tokio walk END stale-epoch task=%llx exp=%d", task_id, (u32)expected_epoch);
            }
            return NULL;
        }

        // Resolve on this task's connection only if it is a per-request anchor, and only
        // from the anchor-time snapshot. A shared task (conn_shared) was anchored to more
        // than one request, so its conn is ambiguous: skip it (fail closed / keep climbing).
        // server_traces_aux is last-write-wins per connection KEY and two requests on one
        // keep-alive inbound connection share the key, so a late lookup there could hand a
        // slightly-late egress of request N the trace of request N+1 (the historical ~1/300
        // release "piled" tail). Every anchor carries a snapshot: tokio_tag_inbound_conn sets
        // tp_valid together with conn_valid, and the only writes that clear tp_valid also
        // set conn_shared or clear conn_valid, so conn_valid && !conn_shared && !tp_valid
        // cannot occur.
        if (task_state->conn_valid && !task_state->conn_shared && task_state->tp_valid) {
            if (egress) {
                bpf_dbg_printk("tokio walk RESOLVE-SNAP task=%llx", task_id);
            }
            // Returned by pointer into the map entry: the egress consumer clears tp.valid
            // in place when it judges the parent stale (parent_trace_is_stale), which
            // fails this anchor closed for the rest of the request — a single-byte
            // write, safe against concurrent readers.
            return &task_state->tp;
        }

        // Stop if there is no parent, or if the parent points back at this task
        // (a self-referential link from pointer reuse), never follow it.
        if (!task_state->parent || task_state->parent == task_id) {
            if (egress) {
                bpf_dbg_printk("tokio walk END no/self-parent task=%llx", task_id);
            }
            return NULL;
        }

        // We need to verify that the parent pointer still refers to the same task recorded at
        // spawn time. Under LRU eviction or Tokio's aggressive Header* allocation reuse, a parent
        // Header pointer can be reused by an unrelated task; following it would resolve a wrong
        // server trace. Fail closed: follow the link only when the parent's version was captured
        // at spawn time (non-zero) AND still matches. An uncaptured version (0) means the parent
        // was not registered when this child was spawned — e.g. a release build where the parent's
        // Cell::new uretprobe was tail-call-skipped — so the link is unverifiable and must not be
        // trusted (it would misattribute on pointer reuse). Legitimate spawn chains always capture
        // a non-zero parent_version, so this does not drop correctly-tracked lineages.
        const tokio_task_key_t parent_key = tokio_task_key(tgid, task_state->parent);
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &parent_key);
        if (!parent_state) {
            if (egress) {
                bpf_dbg_printk("tokio walk END parent-gone parent=%llx", task_state->parent);
            }
            return NULL;
        }
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

// Id-keyed twin of find_tokio_parent_trace: walks the tokio_task_id_state parent chain
// from a task Id. This is the DEBUG-build resolution path (the id map is only populated
// where tokio's TLS setter and Id::next fire — debug; in release it is empty and this
// returns NULL immediately). Task Ids are a monotone counter and never reused, so no
// version validation is needed; instead the walk enforces the monotonicity invariant
// (a parent was created before its child, so parent_id < task id) as a free
// anti-corruption guard.
static __always_inline tp_info_pid_t *
find_tokio_parent_trace_by_id(u32 tgid, u64 task_id, const u8 egress) {
    enum { k_max_tokio_id_depth = 8 };
    // Anchor-epoch expectation carried across hops: when following a child->parent
    // link we must find the parent in the SAME anchor epoch the child recorded at
    // spawn. A mismatch means the parent has been re-anchored to a later request
    // since this lineage was created (e.g. a lazily-spawned worker task outliving
    // its request while its anchor — a keep-alive conn task — moved on): resolving
    // through it would attribute this egress to whatever request the anchor serves
    // NOW. Fail closed instead. The leaf itself carries no expectation (it IS the
    // currently-running task).
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
            // Never seen born (Id::next unresolved/evicted) or deleted at dealloc — the
            // deletion case is load-bearing: a pooled driver's lineage points at the
            // request that first spawned it, and once that request's task died this miss
            // is what fail-closes the reuse instead of resolving the wrong request.
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

        // Resolve only from the anchor-time snapshot (see tokio_task_id_state_t.tp and the
        // Header walk above for why not server_traces_aux). Every anchor carries one, so
        // conn_valid && !conn_shared && !tp_valid cannot occur.
        if (state->conn_valid && !state->conn_shared && state->tp_valid) {
            if (egress) {
                bpf_dbg_printk("tokio idwalk RESOLVE-SNAP id=%llu", task_id);
            }
            // Returned by pointer into the map entry: the egress consumer clears tp.valid
            // in place when it judges the parent stale (parent_trace_is_stale), which
            // fails this anchor closed for the rest of the request — a single-byte
            // write, safe against concurrent readers.
            return &state->tp;
        }

        // Monotonicity invariant: a real parent id is always smaller than its child's.
        // Anything else (0, self, larger) means root or corrupted state — stop.
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
//
// tp is the server trace just saved, never NULL: every anchor carries its snapshot and
// the walks resolve from nothing else (no server_traces_aux fallback).
static __always_inline void
tokio_tag_inbound_conn(u64 id, const connection_info_part_t *conn_part, const tp_info_pid_t *tp) {
    const tokio_thread_state_t *ts =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!ts || !ts->current_task) {
        return;
    }

    // Anchor the id-keyed lineage (the debug path — current_id is only ever non-zero
    // where tokio's TLS setter fires, i.e. debug builds; see tokio_task_id_state.h).
    // Same rules as the Header path below: only tasks seen born (present in the map via
    // Id::next), and a re-anchor to a DIFFERENT request marks the task shared/untrusted.
    // The trace is SNAPSHOTTED into the entry (see tokio_task_id_state_t.tp): resolving
    // from the snapshot instead of a late server_traces_aux[conn] lookup is immune to the
    // conn-key being remapped to a newer request (keep-alive reuse / client ephemeral-port
    // reuse) before a slow egress resolves it.
    // Anchor writes are copy-modify-PUBLISH, never in-place: another CPU may be walking
    // this entry (egress resolution) or reading it for parent-epoch capture (Id::next)
    // at this very moment, and an in-place multi-word write (the ~100-byte tp snapshot
    // especially) has no ordering vs those readers — a torn read under tp_valid=1 would
    // be a chimera traceparent (wrong, propagating). bpf_map_update_elem on a hash map
    // replaces the element atomically for RCU readers: they see the old value or the
    // new one, complete, never a mix.
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
            // Id::next not seen: the task pre-dates OBI's attachment (see the Header path
            // below for why it is anchored anyway). Ids are never reused, so a fresh
            // state needs no version.
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
        // New request served by this anchor -> new epoch. Lineage links recorded
        // under earlier epochs (descendants of PREVIOUS requests that outlived
        // them) stop resolving through this anchor from now on.
        updated->anchor_epoch++;
        bpf_map_update_elem(&tokio_task_id_state, &id_key, updated, BPF_ANY);
        bpf_dbg_printk("tokio handler id conn SET: id=%llu port=%d epoch=%llu",
                       ts->current_id,
                       conn_part->port,
                       updated->anchor_epoch);
        // The id path is authoritative on this thread (see find_tokio_parent_trace_for_thread):
        // never anchor the Header-derived current_task alongside it. In debug that task is
        // a per-worker root shared by every request on the worker; anchoring it would let a
        // later egress running on the root resolve it as the leaf, and the response-time
        // clear below means a sequential re-anchor never trips conn_shared.
        return;
    }

    // Mark the currently-running handler task conn_valid so that any descendant that
    // reaches it via the ancestry walk (including spawn_blocking tasks if registered in
    // tokio_task_state) finds conn_valid=1 directly.
    //
    // A task missing from tokio_task_state is one whose Cell::new OBI did not see: the
    // connection task of a keep-alive connection that pre-dates OBI's attachment, which is
    // the normal case when OBI starts against a running service with persistent client
    // connections. It is anchored like any other task, from a fresh state with version 1
    // (what Cell::new assigns to a never-seen pointer), so children spawned from now on
    // record a trustworthy parent link. The shared-task hazard this used to fail closed
    // on is covered elsewhere: in debug builds the per-worker root never reaches this
    // path (the id path above is authoritative and returns), a task serving a DIFFERENT
    // connection flips conn_shared on its first re-anchor below, and sequential reuse of
    // one connection is bounded by the epoch bump here plus the response-time clear
    // (tokio_untag_inbound_conn).
    const tokio_task_key_t task_key = tokio_task_key(ts->tgid, ts->current_task);
    const tokio_task_state_t *task_state =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_key);

    // Copy-modify-publish, same rationale as the id anchor above (torn multi-word
    // in-place writes vs concurrent walk/inheritance readers).
    tokio_task_state_t *updated = (tokio_task_state_t *)tokio_task_anchor_mem();
    if (!updated) {
        return;
    }
    if (task_state) {
        *updated = *task_state;
    } else {
        *updated = (tokio_task_state_t){.version = tokio_task_incarnation()};
    }

    // If this task is being anchored to a DIFFERENT request than before, it is a
    // shared/long-lived task (a connection/driver task re-stamped once per request,
    // last-write-wins), not a per-request handler. Its connection is therefore
    // ambiguous, so mark it shared and stop trusting it: find_tokio and Cell::new
    // skip a shared task, so egresses running on it — and children spawned from it —
    // fail closed (orphan) instead of resolving to whichever request stamped it
    // last (the source of the cross-request contamination). A genuine per-request
    // handler is anchored exactly once, so it is never marked shared. The FULL key is
    // compared (not just the port): two clients can coincidentally share an ephemeral
    // source port on different addresses, and a port-only check would silently keep a
    // last-write-wins anchor trusted across requests.
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
    // New request served by this anchor -> new epoch. Lineage links recorded under an
    // earlier epoch (descendants of PREVIOUS requests that outlived them — pooled driver,
    // worker task) stop resolving through this anchor from now on (find_tokio_parent_trace
    // epoch check). Bumped even for a shared task so nothing keeps resolving through it.
    updated->anchor_epoch++;
    bpf_map_update_elem(&tokio_task_state, &task_key, updated, BPF_ANY);
    bpf_dbg_printk("tokio handler task conn SET: task=%llx port=%d epoch=%llu",
                   ts->current_task,
                   conn_part->port,
                   updated->anchor_epoch);
}

// Closes the anchor's trust window at SERVER-RESPONSE time (called from
// cleanup_http_server_response_data for HTTP/1 and from delete_server_trace for
// TCP-classified connections). An anchor is valid strictly between its own span-save
// and its response — not until the NEXT request's save. Without this, a MISSED
// span-save (event loss under burst) leaves the conn task holding the PREVIOUS
// request's snapshot and epoch, and the next request's children — which record the
// parent's CURRENT epoch at spawn — pass the epoch check and resolve the predecessor's
// trace (a measured ~1/300 same-side pile under 150x20 load). With the window closed, a
// missed save leaves the anchor INVALID: the children's walks find nothing and orphan
// (fail closed) instead of inheriting the wrong request. It also tightens the
// channel-worker/pooled in-flight residual: handed-off jobs processed after the
// response fail closed even before the next request arrives.
//
// The epoch is bumped as well, so lineage links recorded during the completed request
// stop matching deterministically. Unlike the anchor SET (copy-modify-publish, because a
// torn multi-word conn/tp write could be read as a chimera), the CLEAR is done in place:
// each store is a single word, and any interleaving a concurrent reader can observe only
// moves it toward failing CLOSED (conn_valid=0 first, so a reader mid-clear resolves
// nothing; a not-yet-visible epoch bump merely delays the expiry by that one racing
// walk, which was still within the request's own window). In-place keeps ~250B of
// struct copies off this kprobe-context stack. No-op for non-Tokio threads and for
// unanchored tasks.
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
            bpf_dbg_printk("tokio handler id conn CLEAR: id=%llu epoch=%llu",
                           ts->current_id,
                           id_state->anchor_epoch);
        }
        // Mirror of the anchor: the Header-derived task is never anchored while the id
        // path is active, so there is nothing to clear on it.
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
            bpf_dbg_printk("tokio handler task conn CLEAR: task=%llx epoch=%llu",
                           ts->current_task,
                           task_state->anchor_epoch);
        }
    }
}
