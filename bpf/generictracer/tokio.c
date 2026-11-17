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

// Register conventions: rustc uses the platform C ABI for scalars (a two-scalar struct is
// two scalars) on x86-64 and aarch64, which is what PT_REGS_PARMn / PT_REGS_RC read:
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
// A toolchain change breaks attribution silently; devdoc "Symbol baseline" is re-checked on bumps.

enum { k_tokio_task_none = 0 };

// Entry only: a delete at exit would drop the context at the first await of an in-flight request.
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

// Lineage only, no connection inherited: an egress climbs to the anchor (devdoc "Parent Lookup").
static __always_inline void
tokio_register_task(u64 id, u32 tgid, u64 new_task_ptr, enum tokio_task_origin origin) {
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    // At a wake or a first poll the current task is the waker or the task itself.
    const u8 spawner_known =
        origin != k_tokio_origin_schedule_known && origin != k_tokio_origin_poll;
    const u64 parent_task =
        (spawner_known && thread_state) ? thread_state->current_task : k_tokio_task_none;

    const tokio_task_key_t new_task_key = tokio_task_key(tgid, new_task_ptr);
    const tokio_task_state_t *existing =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &new_task_key);
    // Keeps a count the entry already holds (same spawn registered twice, or a stale
    // occupant); see devdoc "Evicted tasks are not adopted at their wake".
    const u8 inherited = existing && existing->counted;
    const u8 counted = inherited || tokio_slot_inc(tgid, new_task_ptr);

    // Id::next ran right before this constructor on this thread: pair and consume once.
    u64 paired_task_id = 0;
    if (thread_state && thread_state->pending_new_id) {
        paired_task_id = thread_state->pending_new_id;
        thread_state->pending_new_id = 0;
    } else if (existing) {
        // Header reused without an observed dealloc: keep the id twin deletable.
        paired_task_id = existing->task_id;
    }

    bpf_dbg_printk(
        "tokio task_new: new=%llx parent=%llx origin=%d", new_task_ptr, parent_task, (u32)origin);

    tokio_task_state_t new_state = {
        .parent = parent_task,
        .version = tokio_task_incarnation(),
        .task_id = paired_task_id,
        .conn_valid = 0,
        .counted = counted,
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

// Every poll of every scheduler passes here (devdoc "Probe Points"); "self": Tokio is static.
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

    // current_id restarts at 0: trusted only once the TLS setter re-sets it within this poll.
    tokio_thread_state_t new_state = {.current_task = task_ptr, .tgid = tgid, .polled = 1};
    // Nested poll (a runtime inside spawn_blocking): the exit probe restores the outer task.
    const tokio_thread_state_t *outer =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (outer) {
        new_state.prev_task = outer->current_task;
    }
    bpf_map_update_elem(&tokio_thread_state, &id, &new_state, BPF_ANY);

    // Unknown task (pre-attach, inlined spawn hooks, evicted): a root with its own slot count.
    const tokio_task_key_t task_key = tokio_task_key(tgid, task_ptr);
    if (!bpf_map_lookup_elem(&tokio_task_state, &task_key)) {
        tokio_register_task(id, tgid, task_ptr, k_tokio_origin_poll);
    }

    // Lookup first: updating a present LRU key recycles its node on every poll.
    if (!bpf_map_lookup_elem(&tokio_process, &tgid)) {
        const u8 is_tokio = 1;
        bpf_map_update_elem(&tokio_process, &tgid, &is_tokio, BPF_ANY);
    }

    tokio_refresh_obi_ctx(id, tgid, task_ptr);

    return 0;
}

// Clears the task fields so nothing between polls sees a stale parent; the entry stays (polled
// marks a runtime thread) and obi_ctx is left alone.
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

// Cell::<T,S>::new; release inlines small futures' copies, which the two spawn hooks below cover.
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

// bind_inner (every tokio::spawn) and spawn_task (every spawn_blocking) are generic over the
// scheduler only, so they stay out of line when Cell::new is inlined. Spawn-only: unconditional.
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

// spawn_local's counterpart, which also runs on every wake of a local task: only a task
// with no entry is registered, and its slot tells a spawn from the wake of an evicted
// task (devdoc "Evicted tasks are not adopted at their wake").
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

// A reused Header starts clean and a pooled driver's stale id lineage resolves nothing.
static __always_inline void tokio_release_task(u64 id, u32 tgid, u64 task_ptr) {
    const tokio_task_key_t task_key = tokio_task_key(tgid, task_ptr);
    const tokio_task_state_t *dying =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_key);

    bpf_dbg_printk("tokio task release: tid=%d task=%llx", (u32)id, task_ptr);

    if (dying && dying->task_id) {
        const tokio_task_key_t id_key = tokio_task_key(tgid, dying->task_id);
        bpf_map_delete_elem(&tokio_task_id_state, &id_key);
    }
    // Only an entry holding a count releases one: a decrement for a task that may not have
    // taken one (anchor-created entry, evicted entry) could erase a neighbour's.
    if (dying && dying->counted) {
        tokio_slot_dec(tgid, task_ptr);
    }
    bpf_map_delete_elem(&tokio_task_state, &task_key);
}

// Harness::<T,S>::complete, inside the finishing poll: the task is never polled again.
SEC("uprobe/self:tokio_complete")
int GUARDED_PROG(obi_uprobe_tokio_complete, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_ptr = (u64)PT_REGS_PARM1(ctx);
    if (task_ptr == k_tokio_task_none) {
        return 0;
    }

    tokio_release_task(id, tgid, task_ptr);

    return 0;
}

// raw::dealloc: the second chance for a task that never completed (devdoc "Probe Points").
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

    tokio_release_task(id, tgid, task_ptr);

    return 0;
}

// Debug-build id path: tokio's TLS setter, out of line only in debug (release attaches but
// never fires). Closure copies are excluded at attach time (isRustClosureSymbol).
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

// Right before Cell::new on the spawning thread: the id stays pending for the pairing. Inlined
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

    if (thread_state) {
        thread_state->pending_new_id = new_id;
    } else {
        tokio_thread_state_t new_thread_state = {.pending_new_id = new_id, .tgid = tgid};
        bpf_map_update_elem(&tokio_thread_state, &id, &new_thread_state, BPF_ANY);
    }

    return 0;
}
