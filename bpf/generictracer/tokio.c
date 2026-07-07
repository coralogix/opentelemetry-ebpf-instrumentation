// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/tokio_task_state.h>
#include <maps/tokio_thread_state.h> // includes tokio_thread_inbound_conn

#include <shared/obi_ctx.h>

#include <common/connection_info.h>
#include <common/tokio_task.h>

#include <generictracer/maps/pid_tid_to_conn.h>

#include <pid/pid.h>

// Sentinel value matching the Python convention: 0 means "no active task".
enum { k_tokio_task_none = 0 };

// Re-establish obi_ctx (traces_ctx_v1) for the task now running on this OS thread.
// Two reasons it lives on entry:
//
//   1. It must survive release builds.  The poll uretprobe is skipped when raw::poll
//      ends in a tail call (no RET), so an exit-time obi_ctx__del would never run in
//      release. The poll uprobe always attaches, so refreshing here is reliable.
//
//   2. It must follow the task, not flicker. Deleting obi_ctx on every poll exit drops
//      the context at the first await suspension of a still-in-flight request, starving
//      external readers of the (OTEP-shared, pinned) traces_ctx_v1 map.  Refreshing to
//      the task's own owning server trace on each entry keeps the context correct for the
//      whole request and across thread migration, and overwrites any stale context left
//      by a different task that previously ran on this thread.
static __always_inline void tokio_refresh_obi_ctx(u64 pid_tgid, u64 task_id) {
    if (!task_id) {
        obi_ctx__del(pid_tgid);
        return;
    }
    tp_info_pid_t *tp = find_tokio_parent_trace(task_id);
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
// every monomorphized copy of the vtable poll function:
//
//   tokio::runtime::task::raw::poll<T,S>(ptr: NonNull<Header>)
//     PARM1 = ptr (the task Header pointer).
//     This is the free fn whose ADDRESS is stored in each task's vtable; the
//     scheduler reaches it via an indirect call on every poll, for every task type
//     and every scheduler (multi-thread workers, current-thread, AND the blocking
//     pool), in both debug and release. Because its address is taken for the
//     vtable it cannot be inlined.
//
// We do NOT probe tokio::runtime::task::raw::RawTask::poll: that is the thin
// thunk (ldr vtable; ldr vtable.poll; br) that performs the indirect call, and the
// optimiser inlines it into the scheduler's run_task in release — so a probe on it
// never fires on multi-thread workers in release. Probing raw::poll (the vtable
// target) is what makes the feature work in release MT and on the blocking pool.
SEC("uprobe/self:tokio_poll")
int obi_uprobe_tokio_poll(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    const u64 task_ptr = (u64)PT_REGS_PARM1(ctx);
    if (task_ptr == k_tokio_task_none) {
        return 0;
    }

    bpf_dbg_printk("tokio poll_future entry: tid=%d task=%llx", (u32)id, task_ptr);

    tokio_thread_state_t new_state = {.current_task = task_ptr};
    bpf_map_update_elem(&tokio_thread_state, &id, &new_state, BPF_ANY);

    // Refresh (or lazily register) the task's inbound connection at every poll
    // while this thread is serving an inbound request.  This handles two cases:
    //
    //   1. Pre-OBI tasks (never seen by obi_uretprobe_tokio_cell_new): register them
    //      for the first time so find_tokio_parent_trace can see them.
    //
    //   2. Long-lived tasks with a stale conn — e.g. a hyper/reqwest connection-pool
    //      driver task that was created during request A and is being reused for
    //      request B.  Its stored conn points to A's (now-expired) server_traces_aux
    //      entry; refreshing it to B's conn lets the lookup succeed.
    //
    // Guard: skip the refresh when pid_tid_to_conn was overwritten by an outgoing
    // sys_connect.  For an accepted inbound conn, sort_connection_info swaps so
    // d_port becomes the local server port, which differs from orig_dport (the
    // client's remote ephemeral port).  For an outgoing conn, d_port == orig_dport
    // (both are the remote backend port).  Using client conn info as FD_SERVER key
    // would write a wrong entry into tokio_task_state and cause every subsequent
    // server_traces_aux lookup to miss.
    const ssl_pid_connection_info_t *info =
        (const ssl_pid_connection_info_t *)bpf_map_lookup_elem(&pid_tid_to_conn, &id);
    bpf_dbg_printk("tokio poll pid_tid_to_conn: tid=%d info=%p", (u32)id, info);
    if (info) {
        bpf_dbg_printk(
            "tokio poll conn: d_port=%d orig_dport=%d", info->p_conn.conn.d_port, info->orig_dport);
    }
    if (info && info->p_conn.conn.d_port != info->orig_dport) {
        const u32 host_pid = pid_from_pid_tgid(id);
        const tokio_task_state_t *existing =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &task_ptr);

        connection_info_part_t conn_part = {};
        populate_ephemeral_info(
            &conn_part, &info->p_conn.conn, info->orig_dport, host_pid, FD_SERVER);

        // Only (re)write the task's conn when it does not already own one.
        // Inheritance at task_new sets the correct conn for fresh tasks; refreshing
        // a task that already has conn_valid can clobber a correctly-inherited conn
        // with an unrelated request's conn under work-stealing (a migrated task may
        // be polled on a worker whose pid_tid_to_conn holds another request's conn).
        // The refresh is only needed to lazily register pre-OBI / pool tasks that
        // have no conn yet, so it preserves the existing version rather than bumping
        // it (this is a refresh, not a reuse).
        if (!existing || !existing->conn_valid) {
            tokio_task_state_t refreshed = {
                .parent = existing ? existing->parent : k_tokio_task_none,
                .parent_version = existing ? existing->parent_version : 0,
                .version = existing ? existing->version : 1,
                .conn = conn_part,
                .conn_valid = 1,
            };
            bpf_dbg_printk("tokio poll refresh conn: tid=%d task=%llx", (u32)id, task_ptr);
            bpf_map_update_elem(&tokio_task_state, &task_ptr, &refreshed, BPF_ANY);
        }

        // Record at thread level so the ancestry-walk fallback can find the inbound
        // conn even when pool tasks are structurally disconnected.  Always safe to
        // refresh: this reflects which inbound conn the OS thread is serving now.
        bpf_map_update_elem(&tokio_thread_inbound_conn, &id, &conn_part, BPF_ANY);
    }

    // Re-establish obi_ctx for the task now running here. Placed after the
    // conn refresh above so a just-registered conn is visible to the ancestry walk.
    tokio_refresh_obi_ctx(id, task_ptr);

    return 0;
}

// Fires when the Tokio executor finishes polling a task (either suspended at an
// await point or completed).
//
// Clears current_task so stale state is never visible to probes on the next task
// that runs on this thread.
//
// obi_ctx is NOT touched here. It is managed at poll ENTRY by tokio_refresh_obi_ctx:
// refreshing on entry keeps the context correct for the whole request,
// follows a migrated task, overwrites any stale context left by a previous task, and it
// works in release builds where this uretprobe may be skipped (raw::poll
// can end in a tail call, leaving no RET to hook). An obi_ctx__del here would simply not
// run in that case, so it must not live on the exit path.
SEC("uretprobe/self:tokio_poll")
int obi_uretprobe_tokio_poll(struct pt_regs *ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("tokio poll_future exit: tid=%d", (u32)id);

    tokio_thread_state_t *thread_state =
        (tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!thread_state) {
        return 0;
    }

    thread_state->current_task = k_tokio_task_none;
    // Remove the entry entirely so the LRU is not polluted by idle threads.
    bpf_map_delete_elem(&tokio_thread_state, &id);

    return 0;
}

// NOTE (v0.4.0): now largely REDUNDANT with Handler 4 (Cell::new).  The blocking
// task's cell is allocated via Cell::<BlockingTask,BlockingSchedule>::new on the
// handler thread while current_task = the handler (already conn_valid=1), so
// Handler 4 already records parent=handler and inherits the conn.  Handler 3's
// extra write is harmless (same parent/conn; a spurious version bump on a task
// with no children yet).  Kept until the blocking A/B discrimination test confirms
// Cell::new alone covers this path, then a candidate for removal.
//
// Fires when spawn_blocking returns to the caller. This is a regular fn (not
// async), so no context switch happens between the handler's last poll and this
// uretprobe — tokio_thread_state still holds the correct handler task H for this
// thread.
//
// In trace_lifecycle.h already set tokio_task_state[H].conn_valid=1 when
// the inbound HTTP request was first seen.  Here we copy that connection to the
// new blocking task B so that find_tokio_parent_trace resolves B at depth 0
// (conn_valid=1) without touching the racy process-level fallback.
//
// Attached (via demangled-prefix matching in generictracer.go) to the inner free fn
// tokio::runtime::blocking::pool::spawn_blocking<F,R>, which is present in BOTH debug
// and release (the public wrapper tokio::task::blocking::spawn_blocking is inlined away
// in release). It returns the JoinHandle in rax, so this single probe covers all builds.
//
// Return-value ABI (x86-64 SysV):
//   JoinHandle<R> = RawTask = NonNull<Header> — an 8-byte newtype over a pointer.
//   Returned in rax.  PT_REGS_RC(ctx) == the blocking task ptr B.
SEC("uretprobe/self:tokio_spawn_blocking")
int obi_uretprobe_tokio_spawn_blocking(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // JoinHandle<R> is returned in rax.
    const u64 blocking_task_ptr = (u64)PT_REGS_RC(ctx);
    if (blocking_task_ptr == k_tokio_task_none) {
        return 0;
    }

    // The handler task is still "current" — spawn_blocking is synchronous.
    const tokio_thread_state_t *ts =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    if (!ts || ts->current_task == k_tokio_task_none) {
        return 0;
    }

    // Handler task's conn was set by Fix 1 (or its lazy-registration extension)
    // in trace_lifecycle.h before spawn_blocking could be called.  If it is not
    // present or conn_valid=0, there is nothing reliable to propagate.
    const tokio_task_state_t *handler_state =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &ts->current_task);
    if (!handler_state || !handler_state->conn_valid) {
        return 0;
    }

    // Bump the version counter on pointer reuse, mirroring obi_uretprobe_tokio_cell_new,
    // rather than hardcoding 1 (a blocking task pointer can be a reused address).
    const tokio_task_state_t *existing_b =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &blocking_task_ptr);
    const u64 next_version = existing_b ? existing_b->version + 1 : 1;
    const tokio_task_state_t blocking_state = {
        .parent = ts->current_task,
        .parent_version = handler_state->version,  
        .version = next_version ? next_version : 1, // never store 0 (sentinel)
        .conn = handler_state->conn,
        .conn_valid = 1,
    };
    bpf_map_update_elem(&tokio_task_state, &blocking_task_ptr, &blocking_state, BPF_ANY);
    bpf_dbg_printk(
        "tokio spawn_blocking: B=%llx port=%d", blocking_task_ptr, handler_state->conn.port);

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
// Connection inheritance logic (mirrors python.c:_asyncio_Task___init__):
//   1. If the spawning task already has conn_valid, inherit it directly — this
//      propagates the inbound connection key down the task lineage.
//   2. Otherwise fall back to pid_tid_to_conn for the current thread — this
//      covers the case where the very first task is spawned directly from the
//      thread that received the inbound request.
SEC("uretprobe/self:tokio_cell_new")
int obi_uretprobe_tokio_cell_new(struct pt_regs *ctx) {

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // Cell::new returns Box<Cell<T,S>>; Cell is #[repr(C)] with `header` first, so
    // RC (rax on x86-64, x0 on arm64) == &cell == &cell.header == the task Header ptr.
    const u64 new_task_ptr = (u64)PT_REGS_RC(ctx);
    if (new_task_ptr == k_tokio_task_none) {
        return 0;
    }

    // The spawning task is whatever was last recorded as "current" on this thread.
    const tokio_thread_state_t *thread_state =
        (const tokio_thread_state_t *)bpf_map_lookup_elem(&tokio_thread_state, &id);
    const u64 parent_task = thread_state ? thread_state->current_task : k_tokio_task_none;

    bpf_dbg_printk(
        "tokio task_new: tid=%d new=%llx parent=%llx", (u32)id, new_task_ptr, parent_task);

    // Bump the version counter to detect pointer reuse
    const tokio_task_state_t *existing =
        (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &new_task_ptr);
    const u64 next_version = existing ? existing->version + 1 : 1;

    tokio_task_state_t new_state = {
        .parent = parent_task,
        .version = next_version ? next_version : 1, // never store 0 (sentinel)
        .conn_valid = 0,
    };

    // Try to inherit the server connection key from the parent's task state, and
    // record the parent's current version so the ancestry walk can later reject a
    // reused/evicted parent pointer 
    if (parent_task != k_tokio_task_none) {
        const tokio_task_state_t *parent_state =
            (const tokio_task_state_t *)bpf_map_lookup_elem(&tokio_task_state, &parent_task);
        if (parent_state) {
            new_state.parent_version = parent_state->version;
            if (parent_state->conn_valid) {
                new_state.conn = parent_state->conn;
                new_state.conn_valid = 1;
            }
        }
    }

    // If the parent had no connection, check whether this thread is currently
    // serving an inbound request — this handles the first spawn inside a handler.
    // Guard: same as the poll-refresh guard — skip when pid_tid_to_conn was
    // overwritten by an outgoing sys_connect (d_port == orig_dport).
    if (!new_state.conn_valid) {
        const ssl_pid_connection_info_t *info =
            (const ssl_pid_connection_info_t *)bpf_map_lookup_elem(&pid_tid_to_conn, &id);
        if (info && info->p_conn.conn.d_port != info->orig_dport) {
            const u32 host_pid = pid_from_pid_tgid(id);
            connection_info_part_t conn_part = {};
            populate_ephemeral_info(
                &conn_part, &info->p_conn.conn, info->orig_dport, host_pid, FD_SERVER);
            new_state.conn = conn_part;
            new_state.conn_valid = 1;
        }
    }

    bpf_map_update_elem(&tokio_task_state, &new_task_ptr, &new_state, BPF_ANY);

    return 0;
}
