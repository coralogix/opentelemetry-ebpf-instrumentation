// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/tokio_task_id_state.h>
#include <maps/tokio_task_state.h>
#include <maps/tokio_thread_state.h>

#include <shared/obi_ctx.h>

#include <common/connection_info.h>
#include <common/preempt_guard.h>
#include <common/tokio_task.h>

#include <pid/pid.h>

// ABI assumptions shared by every probe in this file. The Rust calling convention is
// unstable, but for a single scalar argument or return value rustc uses the platform C
// convention on x86-64 and aarch64, which is what PT_REGS_PARM1 / PT_REGS_RC read:
//
//   Harness::poll(self: NonNull<Header>)     PARM1 = Header pointer
//   raw::dealloc(ptr: NonNull<Header>)       PARM1 = Header pointer
//   set_current_task_id(id: Option<Id>)      PARM1 = Id (NonZeroU64 niche: None == 0)
//   Cell::new(..) -> Box<Cell<T,S>>          RC    = Header pointer (#[repr(C)], header first)
//   Id::next() -> Id                         RC    = the new Id
//
// A toolchain that changes any of these breaks attribution silently (fail-closed at best),
// which is why the symbol baseline in the devdoc is re-checked on toolchain bumps.

// Same convention as the Python runtime: 0 means "no active task".
enum { k_tokio_task_none = 0 };

// Re-establishes obi_ctx (traces_ctx_v1) for the task now running on this thread. Done at
// poll entry and never at exit: deleting at exit would drop the context at the first await
// of a still-in-flight request, while refreshing at entry follows a migrated task and
// overwrites what a previous task left on the thread.
static __always_inline void tokio_refresh_obi_ctx(u64 pid_tgid, u32 tgid, u64 task_id) {
    if (!task_id) {
        obi_ctx__del(pid_tgid);
        return;
    }
    tp_info_pid_t *tp = find_tokio_parent_trace(tgid, task_id, 0 /* not an egress: silent walk */);
    if (tp && tp->valid) {
        obi_ctx__set(pid_tgid, &tp->tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}

// Poll entry on Harness::<T,S>::poll, attached to every monomorphized copy (see
// generictracer.go for why this symbol): PARM1 is the task Header. Reached by every poll
// of every scheduler, since raw::poll is a tail-call thunk into it, and it keeps a RET in
// release so the exit probe below attaches. "self" because Tokio is statically linked.
SEC("uprobe/self:tokio_poll")
int GUARDED_PROG(obi_uprobe_tokio_poll, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_ptr = (u64)PT_REGS_PARM1(ctx);
    if (task_ptr == k_tokio_task_none) {
        return 0;
    }

    bpf_dbg_printk("tokio poll_future entry: tid=%d task=%llx", (u32)id, task_ptr);

    // current_id and pending_new_id start at 0 on every poll: the id is trusted only when
    // the runtime's TLS setter re-sets it within this poll, which keeps the id path inert in
    // release (where the setter is inlined) even under partial inlining.
    tokio_thread_state_t new_state = {.current_task = task_ptr, .tgid = tgid};
    // Nested poll (a runtime driven from inside a spawn_blocking closure): the exit probe
    // restores the enclosing task.
    const tokio_thread_state_t *outer =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (outer) {
        new_state.prev_task = outer->current_task;
    }
    bpf_map_update_elem(&tokio_thread_state, &id, &new_state, BPF_ANY);

    // Marks the process as Tokio: find_parent_trace then resolves only through the task
    // walks, never through the thread-keyed resolvers.
    const u8 is_tokio = 1;
    bpf_map_update_elem(&tokio_process, &tgid, &is_tokio, BPF_ANY);

    // No connection is derived from the polling thread: on a work-stealing runtime the task
    // polled here may belong to another in-flight request. Connections come only from the
    // anchor (tokio_tag_inbound_conn) through the lineage walk.
    tokio_refresh_obi_ctx(id, tgid, task_ptr);

    return 0;
}

// Poll exit: clears current_task so a probe firing between polls on this thread (a
// runtime-internal Cell::new) cannot take a stale parent. obi_ctx is left alone, see
// tokio_refresh_obi_ctx.
SEC("uretprobe/self:tokio_poll")
int GUARDED_PROG(obi_uretprobe_tokio_poll, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    bpf_dbg_printk("tokio poll_future exit: tid=%d", (u32)id);

    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!thread_state) {
        return 0;
    }

    if (thread_state->prev_task) {
        thread_state->current_task = thread_state->prev_task;
        thread_state->prev_task = k_tokio_task_none;
        tokio_refresh_obi_ctx(id, tgid, thread_state->current_task);
        return 0;
    }

    thread_state->current_task = k_tokio_task_none;
    // Removed entirely so idle threads do not occupy the LRU.
    bpf_map_delete_elem(&tokio_thread_state, &id);

    return 0;
}

// Task creation: uretprobe on Cell::<T,S>::new, the constructor every task-creation path
// goes through (tokio::spawn, spawn_local, spawn_blocking, all schedulers). RC is the task
// Header (Cell is #[repr(C)] with header first). Runs on the spawning thread inside the
// parent's poll, so current_task is the parent. Records lineage only: the child takes the
// parent's incarnation stamp and anchor epoch, never its connection, so an egress must
// climb to the anchor (an inherited copy on a long-lived descendant would outlive its
// request).
SEC("uretprobe/self:tokio_cell_new")
int GUARDED_PROG(obi_uretprobe_tokio_cell_new, struct pt_regs *, ctx) {

    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 new_task_ptr = (u64)PT_REGS_RC(ctx);
    if (new_task_ptr == k_tokio_task_none) {
        return 0;
    }

    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u64 parent_task = thread_state ? thread_state->current_task : k_tokio_task_none;

    // A previous occupant may still have an entry (its dealloc was not observed): only its
    // paired task id is carried over, the version is a fresh stamp.
    const tokio_task_key_t new_task_key = tokio_task_key(tgid, new_task_ptr);
    const tokio_task_state_t *existing =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &new_task_key);

    // Id::next runs right before Cell::new on the spawning thread, so the pending id belongs
    // to this cell. Consumed once.
    u64 paired_task_id = 0;
    if (thread_state && thread_state->pending_new_id) {
        paired_task_id = thread_state->pending_new_id;
        thread_state->pending_new_id = 0;
    } else if (existing) {
        // Keeps the id twin deletable at dealloc when a Header is reused without an
        // observed dealloc.
        paired_task_id = existing->task_id;
    }

    bpf_dbg_printk(
        "tokio task_new: tid=%d new=%llx parent=%llx", (u32)id, new_task_ptr, parent_task);

    tokio_task_state_t new_state = {
        .parent = parent_task,
        .version = tokio_task_incarnation(),
        .task_id = paired_task_id,
        .conn_valid = 0,
    };

    // Pointer-reuse guard (parent_version) and re-anchor guard (parent_epoch) for the walk.
    if (parent_task != k_tokio_task_none) {
        const tokio_task_key_t parent_key = tokio_task_key(tgid, parent_task);
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &parent_key);
        if (parent_state) {
            new_state.parent_version = parent_state->version;
            new_state.parent_epoch = parent_state->anchor_epoch;
        }
    }

    bpf_map_update_elem(&tokio_task_state, &new_task_key, &new_state, BPF_ANY);

    return 0;
}

// Task destruction: entry uprobe on the vtable dealloc slot (PARM1 is the Header), which
// fires reliably in release. Deletes both identity entries, so a reused Header address
// starts clean and a pooled driver's stale id lineage resolves nothing instead of the
// request that first spawned it.
SEC("uprobe/self:tokio_dealloc")
int GUARDED_PROG(obi_uprobe_tokio_dealloc, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_ptr = (u64)PT_REGS_PARM1(ctx);
    if (task_ptr == k_tokio_task_none) {
        return 0;
    }

    const tokio_task_key_t task_key = tokio_task_key(tgid, task_ptr);
    const tokio_task_state_t *dying =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_key);

    bpf_dbg_printk("tokio task dealloc: tid=%d task=%llx", (u32)id, task_ptr);

    if (dying && dying->task_id) {
        const tokio_task_key_t id_key = tokio_task_key(tgid, dying->task_id);
        bpf_map_delete_elem(&tokio_task_id_state, &id_key);
    }
    bpf_map_delete_elem(&tokio_task_state, &task_key);

    return 0;
}

// Debug-build id path. In debug builds the Header-derived current_task at an egress is a
// per-worker root, so the Header walk resolves nothing there; tokio's own TLS still knows
// the running task through set_current_task_id(Option<Id>), called around every poll and
// out of line only in debug (release inlines its call sites: the probe attaches but never
// fires). PARM1 is the id, 0 for None. Closure copies are excluded at attach time
// (isRustClosureSymbol), so PARM1 is never a closure's &Context.
SEC("uprobe/self:tokio_set_task_id")
int GUARDED_PROG(obi_uprobe_tokio_set_task_id, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_id = (u64)PT_REGS_PARM1(ctx);

    // Only an entry created by poll entry: the id is trusted within that poll only.
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!thread_state) {
        return 0;
    }
    thread_state->current_id = task_id;
    return 0;
}

// Id::next, the monotone task-id allocator, called once per task creation right before
// Cell::new on the spawning thread; RC is the new id. Creates the id-keyed lineage entry
// (parent = the spawner's current id, with its anchor epoch) and leaves the id pending for
// the Cell::new pairing. Lineage only, no connection or snapshot. Resolves no usable copy
// in release.
SEC("uretprobe/self:tokio_id_next")
int GUARDED_PROG(obi_uretprobe_tokio_id_next, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 new_id = (u64)PT_REGS_RC(ctx);
    if (!new_id) {
        return 0;
    }

    // Spawns from outside any task (the accept loop, main) have no parent: root.
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u64 parent_id = thread_state ? thread_state->current_id : 0;

    tokio_task_id_state_t new_state = {
        .parent_id = parent_id,
        .conn_valid = 0,
    };

    // The link is valid only for the request the parent serves now.
    if (parent_id) {
        const tokio_task_key_t parent_key = tokio_task_key(tgid, parent_id);
        const tokio_task_id_state_t *parent_state =
            (const tokio_task_id_state_t *)bpf_map_lookup_elem(&tokio_task_id_state, &parent_key);
        if (parent_state) {
            new_state.parent_epoch = parent_state->anchor_epoch;
        }
    }

    const tokio_task_key_t new_id_key = tokio_task_key(tgid, new_id);
    bpf_map_update_elem(&tokio_task_id_state, &new_id_key, &new_state, BPF_ANY);
    bpf_dbg_printk("tokio id_next: tid=%d id=%llu parent_id=%llu", (u32)id, new_id, parent_id);

    // No thread entry yet (a spawn from a non-poll thread): create one carrying only the
    // pending id.
    if (thread_state) {
        thread_state->pending_new_id = new_id;
    } else {
        tokio_thread_state_t new_thread_state = {.pending_new_id = new_id, .tgid = tgid};
        bpf_map_update_elem(&tokio_thread_state, &id, &new_thread_state, BPF_ANY);
    }

    return 0;
}
