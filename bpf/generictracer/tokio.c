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
// which is why the 4-build symbol/ABI matrix (debug/release x legacy/v0) is re-checked on
// toolchain bumps.

// Sentinel value matching the Python convention: 0 means "no active task".
enum { k_tokio_task_none = 0 };

// Re-establish obi_ctx (traces_ctx_v1) for the task now running on this OS thread.
// Two reasons it lives on entry:
//
//   1. Entry always attaches. We probe Harness::poll (see generictracer.go), whose
//      exit uretprobe does fire in release — but keeping the obi_ctx refresh on the
//      always-present entry avoids depending on the exit path for context at all.
//
//   2. It must follow the task, not flicker. Deleting obi_ctx on every poll exit drops
//      the context at the first await suspension of a still-in-flight request, starving
//      external readers of the (OTEP-shared, pinned) traces_ctx_v1 map.  Refreshing to
//      the task's own owning server trace on each entry keeps the context correct for the
//      whole request and across thread migration, and overwrites any stale context left
//      by a different task that previously ran on this thread.
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

// Fires when the Tokio executor begins polling a task. Records the task's Header
// pointer in tokio_thread_state so that later probes on the same OS thread can
// resolve "which task is currently running here".

// SEC target is "self" because Tokio is statically linked into the application
// binary — there is no separate shared library to target.
//
// This handler is attached (via demangled-prefix matching in generictracer.go) to
// every monomorphized copy of the poll function:
//
//   tokio::runtime::task::harness::Harness::<T,S>::poll(self: NonNull<Header>)
//     PARM1 = the task Header pointer.
//     The vtable-stored free fn raw::poll<T,S> is a one-instruction thunk whose body
//     is just `b <Harness::poll>` (a tail call), passing its NonNull<Header> arg
//     through in x0 untouched. So Harness::poll runs on every poll, for every task
//     type and every scheduler (multi-thread, current-thread, AND the blocking pool),
//     in both debug and release — and, unlike raw::poll, it retains a RET in release
//     so the exit uretprobe below actually attaches. See generictracer.go for the
//     full rationale (and the out-of-line fragility caveat).
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

    // current_id and pending_new_id deliberately reset to 0 here (see the struct doc):
    // the task id is trusted only when the runtime's TLS setter re-establishes it WITHIN
    // this poll, which keeps the id path provably inert in release builds (where the
    // setter's call sites are inlined and never fire) even under partial inlining.
    tokio_thread_state_t new_state = {.current_task = task_ptr, .tgid = tgid};
    // Nested poll (a task polling another task synchronously, e.g. a nested runtime
    // driven from inside a spawn_blocking closure): remember the enclosing task so the
    // exit probe restores it instead of leaving the thread with no current task.
    const tokio_thread_state_t *outer =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (outer) {
        new_state.prev_task = outer->current_task;
    }
    bpf_map_update_elem(&tokio_thread_state, &id, &new_state, BPF_ANY);

    // Mark this process as Tokio so resolve_parent_trace fails closed for it:
    // if the ancestry walk finds no owning request, it must not fall through to
    // the generic clone_map walk (meaningless for a shared worker/blocking pool).
    const u8 is_tokio = 1;
    bpf_map_update_elem(&tokio_process, &tgid, &is_tokio, BPF_ANY);

    // A task's inbound connection is established ONLY by lineage: inherited from the
    // parent at task creation (obi_uretprobe_tokio_cell_new) or anchored on the handler
    // task at server-span-save (tokio_tag_inbound_conn). We deliberately do NOT stamp a
    // conn here from the polling thread's pid_tid_to_conn: on a work-stealing runtime the
    // task being polled on this thread may belong to a different in-flight request than
    // the one this thread most recently accepted, so a thread-derived conn would
    // misattribute the egress (fail-closed / correctness-first — same reason the
    // thread- and process-level fallbacks were removed).

    // Re-establish obi_ctx for the task now running here, from its lineage-resolved
    // trace. A task with no resolvable owning request leaves obi_ctx cleared (no guess).
    tokio_refresh_obi_ctx(id, tgid, task_ptr);

    return 0;
}

// Fires when the Tokio executor finishes polling a task (either suspended at an
// await point or completed).
//
// Clears current_task at poll end so a stale task is never visible to probes that
// run on this thread between polls (e.g. a runtime-internal Cell::new spawn), which
// would otherwise capture the wrong parent. We probe Harness::poll, which retains a
// RET in release, so this exit fires reliably in every build.
//
// obi_ctx is NOT touched here. It is managed at poll ENTRY by tokio_refresh_obi_ctx:
// refreshing on entry keeps the context correct for the whole request, follows a
// migrated task, and overwrites any stale context left by a previous task — so the
// context is correct without depending on the exit path at all.
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
    // Remove the entry entirely so the LRU is not polluted by idle threads.
    bpf_map_delete_elem(&tokio_thread_state, &id);

    return 0;
}

// Fires when a Tokio task cell is allocated, via a uretprobe on
// tokio::runtime::task::core::Cell::<T,S>::new — the single constructor that EVERY
// task-creation path funnels through (tokio::spawn / spawn_local / spawn_blocking,
// all schedulers).  Cell::new returns Box<Cell<T,S>>; Cell is #[repr(C)] with
// `header: Header` as its first field, so the returned pointer (PT_REGS_RC) IS the
// task Header pointer used everywhere else — there is no argument-slot or
// pre-vs-post-construction ambiguity.
//
// This replaces the older two-probe scheme (OwnedTasks::bind_inner uprobe +
// LocalOwnedTasks::bind uprobe), which was asymmetric: bind_inner receives the
// built Task<S> (= Header) in PARM2, but LocalOwnedTasks::bind has no such inner
// helper and its entry argument is the raw future, NOT the Header — so the old
// task_new uprobe wrote a garbage key on the spawn_local / LocalSet path (e.g.
// actix-web).  Cell::new sidesteps that entirely by reading the finished cell from
// the return.
//
// Cell::new runs on the SPAWNING thread, synchronously during the parent's poll,
// so current_task is still the spawner (the parent) — same timing as the previous
// bind-time probe.
//
// Connection inheritance: if the spawning task has a usable (non-shared) conn_valid
// connection, the child inherits it, propagating the inbound connection down the task
// lineage. Otherwise the child is left unanchored (conn_valid=0) and fails closed at
// egress — there is no thread-derived fallback (it would misattribute under
// work-stealing). The handler's connection is anchored by the server-span-save path
// (tokio_tag_inbound_conn); descendants pick it up by inheritance.
SEC("uretprobe/self:tokio_cell_new")
int GUARDED_PROG(obi_uretprobe_tokio_cell_new, struct pt_regs *, ctx) {

    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    // Cell::new returns Box<Cell<T,S>>; Cell is #[repr(C)] with `header` first, so
    // RC (rax on x86-64, x0 on arm64) == &cell == &cell.header == the task Header ptr.
    const u64 new_task_ptr = (u64)PT_REGS_RC(ctx);
    if (new_task_ptr == k_tokio_task_none) {
        return 0;
    }

    // The spawning task is whatever was last recorded as "current" on this thread.
    // (Mutable lookup: this handler also consumes pending_new_id — the Id::next result
    // awaiting its Header pairing — below.)
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u64 parent_task = thread_state ? thread_state->current_task : k_tokio_task_none;

    // A previous occupant of this address may still have an entry (its dealloc was not
    // observed). It is consulted only to carry the paired task id over, below; the new
    // entry's version is a fresh incarnation stamp, never derived from it (see
    // tokio_task_incarnation).
    const tokio_task_key_t new_task_key = tokio_task_key(tgid, new_task_ptr);
    const tokio_task_state_t *existing =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &new_task_key);

    // Pair this Header with the task Id generated just before it: task creation calls
    // Id::next then Cell::new back-to-back on the spawning thread, so the pending id
    // recorded by obi_uretprobe_tokio_id_next belongs to THIS cell. Consume-once: the
    // first Cell::new return after Id::next takes the pending id.
    u64 paired_task_id = 0;
    if (thread_state && thread_state->pending_new_id) {
        paired_task_id = thread_state->pending_new_id;
        thread_state->pending_new_id = 0;
    } else if (existing) {
        // A repeated Cell::new return for a Header that already carries an id must not
        // drop the pairing: with task_id=0 the id twin would never be deleted at dealloc
        // and a stale id lineage would outlive its task. Carrying the id over is harmless
        // when this is a genuine reuse without an observed dealloc: the previous occupant
        // is dead, so deleting its id entry at this Header's dealloc is what should have
        // happened anyway. (Several returns per spawn were once observed; they came from
        // the nested Cell::new helpers matched by prefix in debug builds, no longer probed.)
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

    // Record the parent's current version (pointer-reuse guard) and anchor epoch
    // (re-anchor guard). We deliberately do NOT copy the parent's connection: the walk
    // climbs the parent chain to the ANCHORED task and resolves there. An inherited conn
    // copy on a long-lived descendant (a pooled hyper conn driver, an actor/worker task)
    // would outlive its request and keep resolving a keep-alive conn's last-write-wins
    // server_traces_aux entry for LATER requests — a same-side (and, for a worker serving
    // multiple endpoints, cross-side) misattribution. Climbing to the anchor plus the
    // epoch check below makes such reuse fail closed. (Mirror of the id path.)
    if (parent_task != k_tokio_task_none) {
        const tokio_task_key_t parent_key = tokio_task_key(tgid, parent_task);
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &parent_key);
        if (parent_state) {
            new_state.parent_version = parent_state->version;
            new_state.parent_epoch = parent_state->anchor_epoch;
        }
    }

    // No thread-derived bootstrap here. A task whose parent has no connection to
    // inherit is left with conn_valid=0 and fails closed (orphan) at egress. Reading
    // the thread's pid_tid_to_conn as a fallback is a guess: on a work-stealing
    // runtime the connection last seen on this thread frequently belongs to a
    // DIFFERENT in-flight request than the task being created, which misattributes
    // the egress. The handler's connection is anchored authoritatively by the
    // server-span-save path (tokio_tag_inbound_conn), and descendants inherit it — so
    // no thread-derived guess is needed.

    bpf_map_update_elem(&tokio_task_state, &new_task_key, &new_state, BPF_ANY);

    return 0;
}

// Fires when a Tokio task is deallocated, via an entry uprobe on
// tokio::runtime::task::raw::dealloc::<T,S> — the vtable-reached dealloc slot, sibling
// of raw::poll. Being an ENTRY uprobe on an address-taken (non-inlinable) function, it
// fires reliably in release builds — unlike the Cell::new uretprobe, whose RET can be
// tail-call-elided.
//
// It deletes the task's tokio_task_state entry so that a future task which REUSES this
// Header allocation address starts clean. Without it, a reused Header could keep the
// previous occupant's conn_valid entry whenever the reuse's Cell::new uretprobe is
// skipped, and the ancestry walk would then resolve the new task's egress to the OLD
// task's request (misattribution). Deleting here fails closed: a reused Header with no
// re-registration resolves to nothing (orphan) instead of the wrong request. PARM1 is
// NonNull<Header>, the same pointer used as the tokio_task_state key everywhere else.
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

    // Delete the id-keyed twin entry too (debug id path). This is what fail-closes the
    // pooled-driver-reuse hazard: a hyper connection-driver task's id lineage points at
    // the request that FIRST spawned it; once that request's task deallocs here, a later
    // request reusing the pooled driver walks to a deleted entry and orphans instead of
    // resolving the first request's (wrong) trace.
    if (dying && dying->task_id) {
        const tokio_task_key_t id_key = tokio_task_key(tgid, dying->task_id);
        bpf_map_delete_elem(&tokio_task_id_state, &id_key);
    }
    bpf_map_delete_elem(&tokio_task_state, &task_key);

    return 0;
}

// ---- Debug-build id-keyed lineage (see devdocs: id path) ----
//
// In debug builds the per-request task is never the Harness::poll-derived current_task at
// the egress (it collapses to a coarse per-worker root task), so the Header-keyed walk
// above correlates nothing there. But tokio's own thread-local context still knows the
// running task: tokio::runtime::context::set_current_task_id(Option<Id>) is called by the
// runtime around every task poll, and — unlike the poll granularity — it carries the exact
// per-request task Id in debug (measured: the ids match the app's tokio::task::id() at the
// egress and at hyper's dispatch send). In RELEASE its call sites are inlined, so this
// probe attaches to the surviving symbol copy but never fires: the id path is structurally
// inert in release, where the Header walk (which release inlining makes precise) is the
// mechanism. The two cover each other's failure mode.
//
// PARM1 is Option<NonZeroU64> (niche-optimized: None == 0) — the task Id being made
// current, or 0 on clear/restore-to-none. Closure copies of this symbol are excluded at
// attach time (see isRustClosureSymbol in proclang_linux.go), so PARM1 is never a
// closure's &Context here.
SEC("uprobe/self:tokio_set_task_id")
int GUARDED_PROG(obi_uprobe_tokio_set_task_id, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    const u32 tgid = valid_pid(id);
    if (!tgid) {
        return 0;
    }

    const u64 task_id = (u64)PT_REGS_PARM1(ctx);

    // Only update an entry created by poll entry: the id is trusted strictly within the
    // poll that set it (the partial-inlining guard — see tokio_thread_state_t.current_id).
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!thread_state) {
        return 0;
    }
    thread_state->current_id = task_id;
    return 0;
}

// tokio::runtime::task::id::Id::next — the monotone task-Id allocator, called once per
// task creation immediately before the task's Cell::new on the spawning thread. RC = the
// fresh Id. Two jobs:
//
//   1. Create the id-keyed LINEAGE entry: parent_id = the spawning task's current id
//      (accurate in debug via the TLS setter even where the Header-derived parent is a
//      worker-root). Lineage only — no conn/snapshot copies (see below).
//   2. Record the id as pending for the Cell::new that follows, pairing id <-> Header so
//      dealloc can delete the id entry when the task dies (task Ids are never reused, so
//      this deletion is the ONLY id-entry lifecycle besides LRU).
//
// In release this uretprobe resolves no usable copy (the fn is inlined/tail-called away),
// so the id map stays empty there by construction.
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

    // The spawner's current id, if any. Spawns from outside any task (the accept loop,
    // main) legitimately have none -> parent_id = 0 (root), matching the Header path.
    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u64 parent_id = thread_state ? thread_state->current_id : 0;

    tokio_task_id_state_t new_state = {
        .parent_id = parent_id,
        .conn_valid = 0,
    };

    // Capture the parent's CURRENT anchor epoch: this lineage link is valid only for
    // the request the parent is serving right now. A descendant that outlives the
    // request (a lazily-spawned worker/actor task) must not keep resolving through a
    // still-alive anchor that has since moved on to later requests — the walk rejects
    // the link once the epoch no longer matches.
    if (parent_id) {
        const tokio_task_key_t parent_key = tokio_task_key(tgid, parent_id);
        const tokio_task_id_state_t *parent_state =
            (const tokio_task_id_state_t *)bpf_map_lookup_elem(&tokio_task_id_state, &parent_key);
        if (parent_state) {
            new_state.parent_epoch = parent_state->anchor_epoch;
        }
    }

    // Deliberately NO connection/snapshot inheritance here. An id entry only records
    // LINEAGE (parent_id); the connection and its trace snapshot live solely on the
    // ANCHORED task (set at server-span-save), and the egress walk climbs to it. An
    // inherited copy would outlive the request on long-lived descendants — a hyper
    // connection driver or an app worker task spawned during request N keeps serving
    // requests N+1... forever, and a frozen copy of request N's conn/trace on it would
    // resolve LATER requests' egresses to request N (a same-side temporal misattribution
    // the A/B discrimination tests cannot even see, since pooled drivers never cross
    // the A/B host boundary). Climbing to the anchor instead makes reuse fail closed
    // naturally: the anchored ancestor (and the intermediate lineage) dies with its
    // request via the dealloc pairing, so a reused descendant's walk hits a deleted
    // entry and orphans.

    const tokio_task_key_t new_id_key = tokio_task_key(tgid, new_id);
    bpf_map_update_elem(&tokio_task_id_state, &new_id_key, &new_state, BPF_ANY);
    bpf_dbg_printk("tokio id_next: tid=%d id=%llu parent_id=%llu", (u32)id, new_id, parent_id);

    // Leave the id for the Cell::new pairing. If there is no thread entry yet (spawn from
    // a non-poll thread, e.g. the accept loop), create one carrying only the pending id.
    if (thread_state) {
        thread_state->pending_new_id = new_id;
    } else {
        tokio_thread_state_t new_thread_state = {.pending_new_id = new_id, .tgid = tgid};
        bpf_map_update_elem(&tokio_thread_state, &id, &new_thread_state, BPF_ANY);
    }

    return 0;
}
