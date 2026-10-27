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
#include <common/tokio_slots.h>
#include <common/tokio_task.h>

#include <pid/pid.h>

// ABI assumptions shared by every probe in this file. The Rust calling convention is
// unstable, but for scalar arguments and return values (a two-scalar struct is passed as
// two scalars) rustc uses the platform C convention on x86-64 and aarch64, which is what
// PT_REGS_PARMn / PT_REGS_RC read:
//
//   Harness::poll(self: NonNull<Header>)             PARM1 = Header pointer
//   raw::dealloc(ptr: NonNull<Header>)               PARM1 = Header pointer
//   set_current_task_id(id: Option<Id>)              PARM1 = Id (NonZeroU64 niche: None == 0)
//   OwnedTasks::bind_inner(&self, task: Task<S>, ..) PARM2 = Header pointer
//   Spawner::spawn_task(&self, task: Task, ..)       PARM2 = Header pointer (Task is the
//                                                            {UnownedTask, Mandatory} pair)
//   Shared::schedule(&self, task: Notified<..>)      PARM2 = Header pointer
//   Cell::new(..) -> Box<Cell<T,S>>                  RC    = Header pointer (#[repr(C)],
//                                                            header first)
//   Id::next() -> Id                                 RC    = the new Id
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
    tokio_thread_state_t new_state = {.current_task = task_ptr, .tgid = tgid, .polled = 1};
    // Nested poll (a runtime driven from inside a spawn_blocking closure): the exit probe
    // restores the enclosing task.
    const tokio_thread_state_t *outer =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (outer) {
        new_state.prev_task = outer->current_task;
    }
    bpf_map_update_elem(&tokio_thread_state, &id, &new_state, BPF_ANY);

    // A task polled with no entry was never registered (older than OBI's attach, or every
    // spawn hook inlined away) or lost its entry to eviction: it gets a root entry and a
    // slot count of its own, so a later eviction cannot turn its next wake into an
    // adoption. An evicted task counted again leaks its first count at its slot, which
    // only withholds parents there.
    const tokio_task_key_t task_key = tokio_task_key(tgid, task_ptr);
    if (!bpf_map_lookup_elem(&tokio_task_state, &task_key)) {
        tokio_register_task(id, tgid, task_ptr, k_tokio_origin_poll);
    }

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

// Poll exit: clears the task fields so a probe firing between polls on this thread (a
// runtime-internal Cell::new) cannot take a stale parent. The entry itself stays: its polled
// flag is what tells a runtime thread from one that never ran a task. obi_ctx is left alone,
// see tokio_refresh_obi_ctx.
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
    thread_state->current_id = 0;
    thread_state->pending_new_id = 0;

    return 0;
}

// Which probe registered a task, and whether it saw a spawn at all.
enum tokio_task_origin {
    k_tokio_origin_cell_new = 0,
    k_tokio_origin_bind = 1,
    k_tokio_origin_schedule = 2,
    // Shared::schedule for a task whose slot is live: a wake, or a spawn sharing the slot
    // with a live task; no spawner is known, so no parent.
    k_tokio_origin_schedule_known = 3,
    // First poll of a task with no entry: older than OBI's attach, or evicted. A root.
    k_tokio_origin_poll = 4,
};

// Registers new_task_ptr as a child of the task the spawning thread is polling now. Every
// spawn-time caller runs on the spawning thread inside the parent's poll, so current_task
// is the parent; the wake re-registration of an evicted task and the first-poll
// registration of an unknown one record no parent, since the current task is the waker,
// or the task itself. Lineage only: the child takes the parent's incarnation stamp and
// anchor epoch, never its connection, so an egress must climb to the anchor (an inherited
// copy on a long-lived descendant would outlive its request). Overwrites: a previous
// occupant of the Header address may still have an entry (its dealloc was not observed),
// and only its paired task id is carried over, the version is a fresh stamp. A second
// registration of the same spawn (Cell::new, then bind_inner) rewrites the same lineage
// before the task can have children or an anchor. Every registration that finds no counted
// entry takes a slot count, a wake re-registration included, since a live slot may be a
// neighbour's and the task must not depend on it; the entry remembers that it holds one,
// so only that task's dealloc releases it.
static __always_inline void
tokio_register_task(u64 id, u32 tgid, u64 new_task_ptr, enum tokio_task_origin origin) {
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u8 spawner_known =
        origin != k_tokio_origin_schedule_known && origin != k_tokio_origin_poll;
    const u64 parent_task =
        (spawner_known && thread_state) ? thread_state->current_task : k_tokio_task_none;

    const tokio_task_key_t new_task_key = tokio_task_key(tgid, new_task_ptr);
    const tokio_task_state_t *existing =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &new_task_key);
    // A second registration of the same spawn, or a new occupant over a stale entry, keeps
    // a count the entry already holds; an uncounted stale entry (one the anchor created on
    // the spot) does not keep a task from taking its own. An evicted task counted again
    // leaks its first count at its slot, which only withholds parents there.
    const u8 inherited = existing && existing->counted;
    const u8 counted = !inherited;
    if (counted) {
        tokio_slot_inc(tgid, new_task_ptr);
    }

    // Id::next runs right before the task's constructor on the spawning thread, so the
    // pending id belongs to this task. Consumed once.
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
        "tokio task_new: new=%llx parent=%llx origin=%d", new_task_ptr, parent_task, (u32)origin);

    tokio_task_state_t new_state = {
        .parent = parent_task,
        .version = tokio_task_incarnation(),
        .task_id = paired_task_id,
        .conn_valid = 0,
        .counted = inherited || counted,
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
}

// Task creation: uretprobe on Cell::<T,S>::new, the constructor every task-creation path
// goes through (tokio::spawn, spawn_local, spawn_blocking, all schedulers). RC is the task
// Header (Cell is #[repr(C)] with header first). One copy per spawned future type, and the
// optimiser inlines the copies of small futures away (a spawn_local block, spawn_blocking's
// BlockingTask wrapper), which is what the two spawn hooks below cover.
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

    tokio_register_task(id, tgid, new_task_ptr, k_tokio_origin_cell_new);

    return 0;
}

// Spawn-time registration independent of the future type: entry uprobe on the functions
// every spawn passes through after its constructor that are generic over the scheduler
// only, so they keep one out-of-line copy per scheduler however small the future.
// OwnedTasks::<S>::bind_inner takes every tokio::spawn on both runtimes, Spawner::spawn_task
// every spawn_blocking. PARM2 is the new task's Header. Spawn-only functions, so this
// registers unconditionally, like Cell::new.
SEC("uprobe/self:tokio_bind")
int GUARDED_PROG(obi_uprobe_tokio_bind, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 new_task_ptr = (u64)PT_REGS_PARM2(ctx);
    if (new_task_ptr == k_tokio_task_none) {
        return 0;
    }

    tokio_register_task(id, tgid, new_task_ptr, k_tokio_origin_bind);

    return 0;
}

// spawn_local's counterpart. LocalOwnedTasks::bind is generic over the future and inlined
// with Cell::new; the spawn ends in local::Shared::schedule, which also runs on every wake
// of a local task, so a task is registered here only when it has no entry. A task is
// always scheduled before its first poll, so a missing entry belongs to a spawn, or to a
// task seen before whose entry the LRU evicted: the slot count tells them apart, and the
// evicted one is re-registered with no parent, since the current task is its waker. A
// spawn sharing its slot with a live task reads the same way and loses its parent, and
// nothing else: it takes its own count. A task asleep across OBI's attach whose first
// event is a wake by another task has an empty slot and is adopted as that task's child
// (the attach-window limitation in the devdoc). PARM2 is the Notified task, i.e. the
// Header.
SEC("uprobe/self:tokio_schedule")
int GUARDED_PROG(obi_uprobe_tokio_schedule, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_ptr = (u64)PT_REGS_PARM2(ctx);
    if (task_ptr == k_tokio_task_none) {
        return 0;
    }

    const tokio_task_key_t task_key = tokio_task_key(tgid, task_ptr);
    if (bpf_map_lookup_elem(&tokio_task_state, &task_key)) {
        return 0;
    }

    const enum tokio_task_origin origin =
        tokio_slot_live(tgid, task_ptr) ? k_tokio_origin_schedule_known : k_tokio_origin_schedule;
    tokio_register_task(id, tgid, task_ptr, origin);

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
    // Only the task that took a count releases one: an entry the anchor created on the
    // spot, or a wake re-registration, may share its slot with the task the count belongs
    // to, and a task without an entry may have lost its count to eviction, so neither
    // decrements. A count that is never released only withholds parents at its slot.
    if (dying && dying->counted) {
        tokio_slot_dec(tgid, task_ptr);
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
