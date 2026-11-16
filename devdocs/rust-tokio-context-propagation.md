# Rust Tokio Context Propagation

This document describes the architecture and implementation of context propagation for Rust applications built on the [Tokio](https://tokio.rs) async runtime.
It extends the existing context propagation mechanisms documented in [context-propagation.md](context-propagation.md) and follows the same design shape as [python-asyncio-context-propagation.md](python-asyncio-context-propagation.md).

## Table of Contents

- [Current State](#current-state)
- [The Correctness Contract](#the-correctness-contract)
- [Architecture](#architecture)
- [Runtime Model](#runtime-model)
- [Probe Points](#probe-points)
- [Parent Lookup](#parent-lookup)
- [Implementation Details](#implementation-details)
- [Configuration](#configuration)
- [Known Limitations](#known-limitations)
- [Tests](#tests)

## Current State

| Execution pattern | Tokio runtime behavior | Release build | Debug build |
|-------------------|------------------------|---------------|-------------|
| `await` in the handler task (no spawn) | The handler future runs inside the hyper server connection task | Correlated (Header walk) | Correlated (id walk) |
| `tokio::spawn` on a multi-thread runtime, incl. work-stealing migration | The spawned task is enqueued globally and may be **stolen by a different worker thread** | Correlated (Header walk climbs to the anchored connection task) | Correlated (id walk climbs to the anchored connection task) |
| Nested `tokio::spawn` (depth ≥ 2) | Each spawn is a fresh task; each may migrate independently | Correlated (parent-chain walk, ≤ 8 hops) | Correlated (id parent-chain walk, ≤ 8 hops) |
| Direct I/O egress (`TcpStream` written by the spawned task itself) | No connection-driver task in between | Correlated | Correlated |
| Async client (reqwest/hyper), **fresh client per call** | hyper spawns a connection-driver task per new connection, under the request's task | Correlated (the driver task is a child of the request task) | Correlated |
| Async client, **shared client / connection reuse** | One long-lived driver task serves MANY requests over a reused keep-alive connection | **First request per connection correlates; reuse fails closed** (orphan), with the in-flight residual described below | Same |
| `tokio::task::spawn_blocking` | The closure runs on a dedicated **blocking-pool OS thread** | Correlated (the blocking task is registered at `Spawner::spawn_task` under the request task; the Header walk climbs through it) | Correlated via the id walk |
| `tokio::task::spawn_local` on a `LocalSet` (actix-web: one current-thread runtime per worker) | The task never migrates; the handler future is polled inside the per-connection dispatcher task, which anchors | Correlated (registered at `Shared::schedule`, since the spawn's `Cell::new` copy is inlined) | Correlated (id walk) |
| Channel handoff to a long-lived worker task (actor/queue pattern) | A worker task that outlives every request performs the egress | **Fails closed** (orphan) once the spawning request has completed; the job handed off by the request still in flight resolves | Same |
| HTTP/2 inbound or egress | One connection task multiplexes many requests | Not supported; egress fails closed by design (untested) | Same |
| Sync thread outside the runtime (a std-thread listener next to Tokio) | Not a task: the thread never polls | Thread-keyed (its own server span, no clone ancestry) | Same |

**Misattribution is zero in every build and both mangling schemes (legacy `_ZN` and v0
`_R`) across the validation matrix**, including adversarial pool-reuse and channel-handoff
suites designed to force cross-request leakage. Correlation coverage is the same in both
builds; only the mechanism differs (Header walk in release, id walk in debug).

The five suites mount the host cgroup root and tracefs into the OBI container
(`docker-compose-rust-tokio*.yml`), as the other traceparent suites do. Without the cgroup
mount the tpinjector's sockops attaches at OBI's own container cgroup and never enrolls the
server's sockets; without tracefs the FIONREAD compensation tracepoints cannot attach on an
affected kernel and OBI disables context propagation. Either way the backend spans would link
only through the same-host black-box path, and the header path, the one users get across
hosts, would run untested.

## The Correctness Contract

The governing rule, in one line: **resolve a parent trace only through a validated,
epoch-current, anchored task lineage inside the anchor's trust window; otherwise emit
NOTHING.** A missing link produces an orphan span (visibly incomplete, harmless); a wrong
link is injected into the outgoing `traceparent` and silently corrupts the downstream trace
too. Fail fast, never guess, no fallbacks on uncertainty.

### How the contract is enforced (every decision point)

1. **The process and thread gate.** Once a process polls a Tokio task (`tokio_process`,
   keyed by the OBI-view pid), parent resolution on every thread that has polled a task
   (`tokio_thread_state.polled`) uses ONLY the task walks below. Every generic resolver
   (`clone_map` OS-thread ancestry, `cp_support`, the nginx/puma/java thread-keyed
   lookups) is skipped: each is keyed by the handling OS thread, which under work-stealing
   belongs to a different in-flight request (the java resolver's leading
   `server_traces[t_key]` lookup was a measured contamination leak before the gate). A
   thread of that process that never polled a task (a sync listener's thread next to the
   runtime) resolves its own thread-keyed server span and nothing else: exact for a thread
   that read the request itself, and no clone ancestry, which can end at a runtime thread.
2. **Anchored-only resolution.** A trace is resolved only at a task that was explicitly
   anchored to an inbound request at server-span-save time, the one moment "this thread is
   running this request's task" is verifiably true. Lineage nodes carry no connection
   copies (an inherited copy on a long-lived task would outlive its request); the walks
   CLIMB to the anchor.
3. **The anchor is trusted only inside its trust window: from the server-span save to
   the HTTP response.** The response path untags the task (connection and snapshot
   invalidated, epoch advanced). Whatever runs on that task afterwards, a fire-and-forget
   spawn or the connection task's next poll, resolves nothing until the next request
   anchors it again.
4. **Every lineage link is validated, or refused.** Header path: `parent_version` must be
   non-zero and still match (pointer-reuse guard; an unverifiable link is never followed).
   Id path: `parent_id < id` (ids are monotone; anything else is corruption). Both paths:
   the recorded `parent_epoch` must equal the parent's current `anchor_epoch`, so a lineage
   created during request N stops resolving the moment its anchor serves request N+1.
   Depth is capped at 8. Any failure at any hop → NULL.
5. **Ambiguity is poisoned, not arbitrated.** A task re-anchored to a DIFFERENT
   connection key (full key compared: address, pid, port, type) is `conn_shared`: its
   connection and snapshot are never trusted again.
6. **Resolution reads a frozen snapshot and nothing else.** The anchor stores the owning
   trace at anchor time; the walks resolve from that snapshot or not at all. There is no
   lookup into the connection-keyed `server_traces_aux` map, which is last-write-wins and
   remapped by keep-alive reuse before a late egress could read it. The walks hand the
   consumer a per-CPU copy of the snapshot, re-checking the anchor epoch (and the
   incarnation stamp on the Header path) after the copy: a preallocated LRU element freed
   by a concurrent re-anchor returns to the free list with no grace period, so a pointer
   into it could be rewritten under the reader.
7. **State that could go stale is reset or destroyed, not reused.** `current_id` is zeroed
   at every poll entry and trusted only if the runtime's own TLS setter re-set it within
   that poll; `Harness::complete` deletes both identity records at task end; `Cell::new` and
   the spawn-only hooks re-initialize a reused Header entry; `Shared::schedule` records no
   parent for a task whose slot count says its entry was evicted (the task current at a
   wake is the waker, not the spawner); anchor writes are
   copy-modify-publish (a single `bpf_map_update_elem`), so concurrent readers see a
   complete old or new value, never a torn one; every entry is deleted when the process
   exits.
8. **There are no fallback tiers.** Earlier revisions had thread-level and process-level
   last-write-wins fallbacks; each was measured misattributing under concurrency (up to
   ~35% in adversarial tests) and all were removed. The id walk is NOT a fallback: it is
   a second exact identity system (tokio's own task-id TLS), authoritative wherever it is
   active, validated by the same rules.

### The exact, exhaustive list of residual wrong-parent risks

The contract holds everywhere except the following, all documented in
[Known Limitations](#known-limitations); nothing else can produce a wrong parent:

1. **The in-flight window of a shared task.** A long-lived task (a channel worker, a
   pooled connection driver) spawned under request N serves another request's job while N
   is still open. The lineage lookup is exact but its premise (lineage = ownership) is
   false for handed-off work, and the runtime carries no signal for whose job it is. Same
   endpoint, same side only: a shared task serving two inbound connections fails closed on
   the epoch guard. Measured across the 2026-10 runs: a few same-side piles per run at
   most (pooled client), zero cross-side everywhere.
2. **Fully-stripped binaries** (the one true contract violation): no symbols → no probes
   → the process gate is never set → the process degrades to the GENERIC thread-keyed
   resolvers, which can misattribute under work-stealing. Undetectable at runtime (the
   Rust-detection symbol is stripped too); ship Rust binaries with symbols retained.

The test suite enforces the contract in both observable directions: `contaminated == 0`
(cross-endpoint joins) is gated on every case, and `piled == 0` (same-endpoint temporal
joins, the form cross-A/B testing is blind to) is gated everywhere except the two shared-task
suites, where the residual is logged and watched instead. `contaminated` counts the cross-side
**client** span, the walk's own output; a cross-side backend span without its client span is
`stray`, OBI's generic same-host correlation colliding on a shared ephemeral port (see
[Known Limitations](#known-limitations)), logged and not gated.

## Architecture

### Why thread-only correlation is not enough

OBI normally assumes that work running on the same OS thread belongs to the same logical request: it keys the in-flight request connection by thread id in `pid_tid_to_conn`. That assumption breaks for the Tokio multi-thread runtime:

- one runtime drives many requests across a shared pool of worker threads,
- a task created on the handler's thread can be **stolen and resumed on a different worker** before it makes its outgoing call,
- `spawn_blocking` moves work onto a blocking-pool thread that never ran the handler at all.

Measured with the discrimination suite (`TestRustTokioProbeDiscrimination`, 150 requests per
side, release build, Linux 6.8 arm64): OBI from `main` links 40–46 outbound spans per supported
shape (`spawn_blocking`, direct egress, `tokio::spawn`) to the other side's request and 15–19
to the right one; this branch links 71–150 to the right one and none wrongly on the same build.

To recover the correct parent trace, the tracer needs the current logical Tokio **task** rather than only the current OS thread.

### Two complementary task-identity mechanisms

The implementation tracks task identity two ways, because no single signal survives both
build profiles:

1. **Header-keyed lineage (the release mechanism).** `Harness::poll` entry/exit maintains
   the currently-polled task's `Header*` per thread; `Cell::new` and the two spawn hooks
   (`bind_inner` / `spawn_task`, `Shared::schedule`) record each task's parent Header at
   creation. In release builds the optimizer inlines the async machinery
   into the per-request task's poll frame, so the `Header*` current at the egress is the
   request task, or a child of it (hyper's connection-driver task for a fresh client), and
   the ancestry walk resolves it. In debug builds this signal collapses: the egress
   observes one of a few coarse per-worker "root" tasks.

2. **Id-keyed lineage (the debug mechanism).** Tokio's runtime maintains its own
   thread-local "current task Id" (what `tokio::task::id()` returns) through
   `tokio::runtime::context::set_current_task_id(Option<Id>)`, called around every task
   poll. In debug builds that setter exists out-of-line and fires with exact per-request
   task Ids precisely where the Header signal collapses. `Id::next` (the monotone task-Id
   allocator, called once per task creation) provides the id-keyed parent chain. In
   release builds the setter's call sites are inlined (it never fires) and `Id::next`
   resolves no usable copy, so the id state is never populated: the id path is
   structurally inert in release, and the Header path structurally misses in debug.

**The id path is authoritative.** Whenever `current_id` is set on the thread (the setter
fired within the current poll), only the id walk runs and only the id entry is anchored.
The Header walk runs only when no id is set. Had a debug worker root ever been anchored
through the Header path, it would resolve as the leaf for every request on that worker;
the authoritative rule makes that impossible once the setter probe is attached (see the
attach window in Known Limitations).

Both resolve through the same fail-closed contract: walk the recorded per-task ancestry to
the task anchored to an inbound request, inside its trust window, or return nothing.

## Runtime Model

The design depends on these Tokio behaviors (all verified by disassembly, source reading of the pinned version, or measurement):

1. Every task poll runs through `tokio::runtime::task::harness::Harness::<T,S>::poll`, reached on every poll for every scheduler (multi-thread workers, current-thread, and the blocking pool) in both debug and release. The vtable-stored `raw::poll::<T,S>` is a one-instruction thunk that tail-calls it, so `Harness::poll` is the universal poll point; unlike `raw::poll`, it retains a `RET` in release, so a uretprobe on it fires reliably.
2. Every async task-creation path allocates the task's cell through `tokio::runtime::task::core::Cell::<T,S>::new`. It runs synchronously on the spawning thread while the spawning task is still "current". `Cell` is `#[repr(C)]` with `header` first and `Cell::new` returns `Box<Cell>`, so the returned pointer is the task `Header`. `Cell::new` has one copy per spawned future type, and in release the optimizer inlines the copies of small futures (a `spawn_local` block, `spawn_blocking`'s `BlockingTask` wrapper) into their spawn site, so some tasks are never seen there. Every spawn then continues through a step that is generic over the scheduler only, one out-of-line copy per scheduler however small the future, with the new `Header` as its second argument: `OwnedTasks::<S>::bind_inner` for `tokio::spawn` on both runtimes (tokio factored it out of `bind<T>` as "the part that's the same for every type of future"), `blocking::pool::Spawner::spawn_task` for `spawn_blocking`, and `local::Shared::schedule` for `spawn_local` (`LocalOwnedTasks::bind` is generic over the future and inlined with `Cell::new`). Measured on the actix-web (`LocalSet`) release server: 36 task types polled, 22 with a `Cell::new` copy, the `spawn_local` ones among the missing.
3. Task creation calls `tokio::runtime::task::id::Id::next` (a monotone `u64` counter; **ids are never reused**) immediately before the task's `Cell::new` on the spawning thread. This adjacency is what pairs a task's Id with its Header.
4. The runtime maintains the TLS current-task id via `tokio::runtime::context::set_current_task_id`, called on poll enter (set) and exit (restore), including around **blocking-pool** task polls, which is why the id walk can correlate `spawn_blocking` in debug.
5. Tokio is **statically linked** into the application binary, so all probes target the executable itself (`SEC("uprobe/self:...")`).
6. Every task whose future finishes or is cancelled passes through `tokio::runtime::task::harness::Harness::<T,S>::complete`, inside the poll that finished it and before its memory is freed, whoever drops the last reference afterwards. A completed task frees itself through `Harness::dealloc` inlined into `complete` and `drop_reference`; the vtable thunk `raw::dealloc` runs only when a `Task` or `Notified` handle is the last reference dropped, so it is not a task-end signal (0 of 128,000 tasks in the integration suites reached it). `complete` keeps one out-of-line copy per `<T,S>` pair in release, the same count as `Harness::poll` (37 in the test server, 10 in the backend), as a local symbol with an `.llvm.` suffix that both demanglers ignore.

### Symbol baseline

Measured on the integration servers and their backend (tokio 1.52.3, axum 0.7.9, hyper
1.10.1, reqwest 0.13.4, actix-web 4.18.1 with actix-rt 2.15.0, rust 1.99.0), arm64, Linux
6.8. Copies = monomorphized symbol copies the instrumenter attached after exact-path
matching, as the `rust path resolved` log lines report them, on the rust 1.99.0 (v0)
build. The rust 1.96.0 (legacy mangling) build gives the same counts except one more
`Cell::new` copy in the axum release server and backend (31 / 9). tokio 1.54.1 keeps the
release counts within one copy of this table on both toolchains (except the backend built
next to the actix server, which resolves one `Cell::new` copy instead of 8 on rust 1.99.0)
and reports half the debug counts (37 / 10 for the axum pair, 44 / 10 for the actix pair),
still equal across the four task probes; the suites pass on all three builds. "Fires" = the
probe is observed at runtime.

| Probe | Release: axum server / backend | Release: actix server / backend | Debug: axum server / backend | Debug: actix server / backend | Fires in release | Fires in debug |
|---|---|---|---|---|---|---|
| `Harness::poll` entry + exit | 37 / 10, all with `RET` | 42 / 10 | 74 / 20 | 88 / 20 | yes | yes |
| `Cell::new` (return) | 30 / 8 | 25 / 8 | 74 / 20 | 88 / 20 | yes | yes |
| `OwnedTasks::bind_inner` | 2 / 1 | 4 / 1 | 2 / 2 | 4 / 2 | yes | yes |
| `Spawner::spawn_task` | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 1 | yes | yes |
| `Shared::schedule` | absent / absent | 1 / absent | absent / absent | 1 / absent | yes, actix | yes, actix |
| `Harness::complete` | 37 / 10 | 44 / 10 | 74 / 20 | 88 / 20 | yes | yes |
| `raw::dealloc` | 28 / 10 | 34 / 10 | 74 / 20 | 88 / 20 | only for a handle-drop last reference | same |
| `set_current_task_id` | 1 / 1, call sites inlined | 1 / 1 | 1 / 1 | 1 / 1 | never | yes |
| `Id::next` (return) | no usable copy | no usable copy | 1 / 1 | 1 / 1 | never | yes |

In debug every generic task function has one copy per `<T,S>` pair, hence the equal counts;
release inlines part of the poll and creation paths, hence the uneven ones.
`Shared::schedule` exists only in a binary with a `LocalSet` (the actix server),
`Spawner::spawn_task` only in one that links the blocking pool.

Program sizes at this baseline (x86 object; arm64 was equal when both were measured;
instructions, the branch offset limit is 32,767 per program): `obi_uprobe_tokio_poll` 624,
`obi_uretprobe_tokio_poll` 442, `obi_uretprobe_tokio_cell_new` 399, `obi_uprobe_tokio_bind`
399, `obi_uprobe_tokio_schedule` 426, `obi_uprobe_tokio_complete` 339,
`obi_uprobe_tokio_dealloc` 339, `obi_uprobe_tokio_set_task_id` 239,
`obi_uretprobe_tokio_id_next` 374; `obi_protocol_tcp`, which inlines the parent lookup,
19,890, and `obi_continue_protocol_http_tp_commit`, which inlines the inbound anchor,
5,365. The Tokio programs and `obi_continue_protocol_http_tp_commit` pass the verifier on
5.10.0 and 5.8; `obi_protocol_tcp` fails on 5.8 with the same error as main's object.

Cost, measured with `hey` at 500 requests/s for 60 s per endpoint on a 4-vCPU Lima VM
(Linux 6.8, arm64; app alone, OBI from `main`, this branch with the probes on, this
branch with `capture.runtimes.rust.enabled: false`): on `/ws-spawn` the server's CPU is
175 % alone, 167 % under `main`, 166 % with the probes and 169 % with them off; p99
23.1 / 23.4 / 22.1 / 23.5 ms; OBI's own CPU 2.9 % in every OBI leg. On `/blocking` the
four legs are within noise of each other. Per probe (`bpf_stats`): poll entry 323 ns,
poll return 127 ns, `bind_inner` 197 ns, `complete` 237 ns, `Cell::new` 375 ns.

The x86 integration matrix has not run yet; re-check this table on every toolchain bump
(see the inlining limitation below).

## Probe Points

Because Tokio's internal symbols are generic and monomorphized, and are emitted under two different Rust mangling schemes, the Go-side instrumenter attaches each program to *every* matching symbol by demangled path (`FindRustSymbols`). Closure bodies are excluded at match time (see [Closure symbols are excluded](#closure-symbols-are-excluded-from-path-matching)).

### `Harness::poll` (poll entry/exit) — `tokio_poll`

`tokio::runtime::task::harness::Harness::<T,S>::poll` runs a task poll. PARM1 is the task `Header*`.

- **Entry** (`obi_uprobe_tokio_poll`): records `current_task = PARM1` in `tokio_thread_state`, **resets `current_id` and `pending_new_id` to 0** (see [the trust guard](#the-current_id-poll-scoped-trust-guard)), marks the process in `tokio_process`, and refreshes `obi_ctx` for the task now running here.
- **Exit** (`obi_uretprobe_tokio_poll`): zeroes the thread's task fields so a stale task is never visible between polls; the entry stays, its `polled` flag marking the thread as a runtime thread.

Why `Harness::poll` and not `raw::poll` or `RawTask::poll`: `RawTask::poll` is inlined into the scheduler in release; `raw::poll` is a one-instruction thunk that tail-calls `Harness::poll` with no `RET`, so a uretprobe on it is silently skipped in release, leaving `current_task` stale between polls. `Harness::poll` retains its `RET` in release (verified on every copy). It is out-of-line only by the optimiser's choice: the instrumenter warns when any copy of a path attaches without return offsets, so a toolchain that changes this is visible in the logs.

### `Cell::new` (task creation) — `tokio_cell_new`

Uretprobe; `PT_REGS_RC` is the new task's `Header*` (`Cell` is `#[repr(C)]`, header first). Records the Header-keyed lineage entry (`tokio_register_task`): parent = the thread's `current_task`, the parent's current `version` (pointer-reuse guard) and `anchor_epoch` (re-anchor guard), and a `version` of its own. No connection is copied from the parent: the walk climbs to the anchor. Additionally **consumes `pending_new_id`**, the Id generated by the immediately-preceding `Id::next` on this thread, storing it as `tokio_task_state.task_id`, which pairs the task's Id with its Header for lifecycle cleanup. Consume-once: should a creation path ever produce a second return, the extra entry gets `task_id = 0`, which can only degrade to a missing id lineage (orphan), never a wrong one.

### `OwnedTasks::bind_inner`, `Spawner::spawn_task` (spawn-time registration) — `tokio_bind`

Entry uprobe on the two spawn-only functions that follow the constructor and are generic over the scheduler, not the future (Runtime Model, item 2): `tokio::runtime::task::list::OwnedTasks::<S>::bind_inner(&self, task, notified)` for every `tokio::spawn`, `tokio::runtime::blocking::pool::Spawner::spawn_task(&self, task, rt)` for every `spawn_blocking`. `PT_REGS_PARM2` is the new task's `Header*` in both (`Task<S>` is the Header pointer; the blocking `Task` is a `{UnownedTask, Mandatory}` pair passed as two scalars, Header first). Same registration as `Cell::new`, unconditional: after an out-of-line `Cell::new` it rewrites the same lineage before the task can have children or an anchor; after an inlined one it is the registration. `spawn_task` is flagged `MayBeInlined`: a binary that never links the blocking pool has no such symbol.

### `Shared::schedule` (spawn_local registration) — `tokio_schedule`

Entry uprobe on `tokio::task::local::Shared::schedule(&self, task)`; `PT_REGS_PARM2` is the `Notified` task, i.e. the `Header*`. The spawn of every `spawn_local` ends here, but so does every wake of a local task, so the program registers only a task that has **no entry**. A task is always scheduled before its first poll, so a missing entry belongs to a spawn, or to a task seen before whose entry the LRU evicted. The slot count (`tokio_task_slots`, see [Evicted tasks are not adopted at their wake](#evicted-tasks-are-not-adopted-at-their-wake)) tells them apart: a task whose slot is live is re-registered with **no parent**, since the task current at a wake is the waker, not the spawner. A task asleep across OBI's attach whose first event is a wake by another task has an empty slot and is adopted as that task's child (see the attach window in Known Limitations). Flagged `MayBeInlined`: a binary without a `LocalSet` has no such symbol.

### `Id::next` (task-id allocation) — `tokio_id_next`

`tokio::runtime::task::id::Id::next`: uretprobe, RC = the fresh task Id. Two jobs:

1. Creates the **id-keyed** lineage entry in `tokio_task_id_state`: `parent_id` = the spawning task's `current_id` (accurate in debug via the TLS setter, even where the Header-derived parent is a worker root), plus the parent's **anchor epoch** captured at spawn time. Lineage only, no connection or snapshot copies.
2. Records the id in `pending_new_id` for the `Cell::new` pairing.

Resolves no usable copy in release (inlined), so the id map stays empty there by construction. The probe is flagged `MayBeInlined`, which silences the partial-resolution warning for exactly this expected case.

### `set_current_task_id` (TLS current-task id) — `tokio_set_task_id`

`tokio::runtime::context::set_current_task_id(Option<Id>)`: entry uprobe; PARM1 is the id being made current (niche-optimized `Option<NonZeroU64>`: `None == 0`). Updates `tokio_thread_state.current_id`, only on an entry created by poll entry (the trust guard). Fires only in debug builds (call sites inlined in release). A belt-and-braces `id > u32::MAX` skip guards against any unexpected shim passing a pointer; skipping a genuine huge id could only orphan.

### `Harness::complete` (task completion) — `tokio_complete`

Entry uprobe on `Harness::<T,S>::complete` (PARM1 = `Header*`: the harness is one pointer passed by value), reached by every task whose future finished or was cancelled, inside the poll that finished it. Deletes the task's Header-keyed entry so a reused `Header` allocation starts clean, **deletes the id-keyed twin entry** (via the paired `task_id`), and releases the task's slot count if the entry says it took one. The task is never polled again; a child still linking to it fails closed on the walk.

### `raw::dealloc` (task destruction) — `tokio_dealloc`

Entry uprobe on the vtable dealloc slot (PARM1 = `Header*`), the same release as `Harness::complete`. A completed task frees itself through `Harness::dealloc` inlined into `complete` and `drop_reference`, so this thunk runs only when a `Task` or `Notified` handle is the last reference dropped (a `Notified` discarded at shutdown, a blocking task whose `JoinHandle` went first): the second chance, not the common path. The id deletion is what fail-closes the pooled-driver-reuse hazard: a driver task's id lineage points at the request that first spawned it; once that request's tasks are deallocated, a later request reusing the pooled driver walks into a miss (orphan) instead of resolving the first request's trace.

## Parent Lookup

When a Tokio client request needs a trace parent (at egress, via `find_tokio_parent_trace_for_thread`), the lookup is fail-closed:

1. If the thread has a `current_id` (set within the current poll: debug builds), the **id walk** (`find_tokio_parent_trace_by_id`) runs and nothing else.
2. Otherwise the **Header walk** (`find_tokio_parent_trace`) runs from `tokio_thread_state.current_task`.

Both walks climb the recorded parent chain for at most 8 hops. At every hop the entry must exist (a deleted or evicted entry ends the walk), and from the second hop on the entry's `anchor_epoch` must equal the `parent_epoch` the child recorded at spawn. The first entry that is anchored (`conn_valid`), not shared (`conn_shared == 0`) and inside its trust window resolves from its **anchor-time trace snapshot**; there is no other source. To follow a link, the Header walk needs a non-zero `parent_version` that still matches the parent's `version` (pointer reuse), the id walk needs `parent_id < id` (monotone ids, never reused). Anything else returns NULL: orphan, never a guess.

For a Tokio process (marked in `tokio_process` on first poll), `find_parent_trace` resolves a thread that has polled a task **only** via these walks; every generic resolver (`clone_map`/process ancestry, `cp_support`, nginx/puma/java) is skipped, because each is either for another runtime or keyed by the handling OS thread, which under work-stealing belongs to a different in-flight request. A thread of that process that never polled a task keeps its own `server_traces[t_key]` entry as the only source, with no clone ancestry: a sync listener's threads next to the runtime stay correlated as before the probes.

## Implementation Details

### Request ownership is captured at the server-span save

The task running when the inbound server span is saved is anchored to the request (`tokio_tag_inbound_conn`, driven from the generic server-span-save path): the thread is, right then, genuinely running the connection/handler task for that request. The identity anchored follows the authoritative rule (`current_id` if set, else `current_task`). Each anchor bumps the entry's `anchor_epoch` (one epoch per request served) and stores the request's connection key and the trace snapshot. A task OBI never saw born, typically a keep-alive connection task created before OBI attached, gets a fresh entry at this point: it has no lineage above it, so it can resolve only its own egresses and those of tasks spawned under it afterwards, which is exactly its request.

### The trust window closes at the response

When the server's HTTP/1 response is written (`cleanup_http_server_response_data`) or the connection's server trace is deleted on the TCP-classified path (`delete_server_trace`), the task is untagged (`tokio_untag_inbound_conn`): `conn_valid` and `tp_valid` are cleared in place, in that order so a reader mid-clear fails closed, and the epoch advances. From then on the task resolves nothing until the next request anchors it again. The integration suite asserts from OBI's debug log that every anchor opened was closed. The untag clears the task current on the thread that writes the response: a server that reads a request on one task and writes its response on another (the two halves of one stream split across tasks) never closes the reader's window until the next request re-anchors it, so a task spawned under the reader between the two could resolve the finished request. No HTTP framework splits before the response; the shape is noted, not handled.

### A task re-anchored across requests is poisoned (`conn_shared`)

If an anchored task is re-anchored to a **different** connection key, it is a shared/long-lived task (e.g. a connection driver) whose connection is ambiguous last-write-wins: it is marked `conn_shared`, its snapshot is invalidated, and it is never resolved from again. The comparison uses the **full** connection key (address, pid, port, type), not just the port: two clients can coincidentally share an ephemeral source port on different addresses.

### Anchored entries snapshot the trace at anchor time (both paths)

`server_traces_aux[conn]` is last-write-wins per connection key. A slightly-late egress could resolve the key AFTER a later request remapped it: two requests on a keep-alive inbound connection share the key (measured ~1/300 per endpoint before the snapshot), a blocking-pool call can outlive the key's owner, and a new connection can reuse a just-closed connection's client ephemeral port. The anchored entry therefore stores a **snapshot** of the owning trace, taken at anchor time, and the walks resolve from the snapshot only. Every anchor carries one: the tag sets `tp_valid` together with `conn_valid`, and the only writes that clear `tp_valid` also set `conn_shared` or clear `conn_valid`. A Header-keyed snapshot is safe because `Cell::new` re-initializes a reused entry, `raw::dealloc` deletes freed entries, anchor writes are copy-modify-publish and a `conn_shared` flip invalidates it; task Ids are never reused, so the id-side snapshot has no reuse surface at all. The walks return a per-CPU copy of the snapshot, not a pointer into the map: a preallocated LRU element that a concurrent re-anchor replaces goes back to the free list with no grace period and can be rewritten under a reader still holding it, so the copy is discarded when the anchor epoch, or the incarnation stamp on the Header path, changed across it. The consumer's in-place staleness write lands on the copy.

### Keys are (OBI-view pid, identity) and state dies with the process

Header pointers and task ids are process-local: two Tokio processes on one host produce colliding pointers and overlapping id counters. Every task entry is keyed by `tokio_task_key_t {tgid, id}`, where `tgid` is the pid as OBI sees it (`valid_pid()`, the same value the process gate uses, so the two always agree). `tokio_thread_state` records that pid too; a thread's entry is deleted at its exit (the `sys_exit` kprobe, where `clone_map` is cleaned too), so a reused tid starts unmarked. When OBI stops instrumenting a process (`BlockPID`), the Go side deletes its `tokio_process` flag and, only if that delete succeeds (so a non-Tokio exit costs one failed delete and nothing more), scans the three task maps and removes every entry of that pid. Without the purge a new process reusing the pid would inherit anchored entries from the dead one; LRU eviction alone would not clear them in time. `BlockPID` follows the discovery's removal event, raised when a pid is absent from the next `/proc` scan (`discovery.poll_interval`): a pid reused inside one interval raises none, and the new process inherits the dead one's mark and entries until its own polls, registrations and anchors rewrite them. Only a task the new process never registered (a `spawn_local` task whose Header address still carries a stale anchored entry, which the schedule hook leaves alone) could resolve the dead request's trace in that window, and only until that entry's dealloc or re-anchor. With the BPF pid filter off the maps are keyed by the host pid and the purge, keyed by the OBI-view pid, misses: those entries live until LRU eviction.

### The `current_id` poll-scoped trust guard

Poll entry resets `current_id` to 0; only the TLS setter firing **within the current poll** re-establishes it. This makes the id path provably inert in release even under *partial* inlining: if a future toolchain inlines only some of the setter's call sites, a stale id left by a surviving call site is wiped at the next poll entry before any egress could trust it. (Today the setter fires zero times in release, measured, and `Id::next` doesn't resolve there, so the id map is empty; the guard is defense in depth.)

### Task pointer reuse is stamped (Header path only)

Tokio reuses `Header*` addresses: a freed task cell is handed straight back for the next task of the same size in the same process. `Harness::complete` deletes the dead task's entry, which protects the newcomer from the old anchor, but not the links that the dead task's surviving children still hold to the address (a fire-and-forget child whose connection task closed). Each Header entry therefore carries a `version` that is an **incarnation stamp**: the monotonic creation time (`bpf_ktime_get_ns`). A child records `parent_version` at spawn and the walk follows the link only when the parent's current stamp still matches; two occupants of one address cannot share a stamp (the second is created microseconds after the first was freed, against a clock tick of tens of nanoseconds), and an unverifiable `parent_version == 0` link is never trusted. A counter restarting at 1 for each occupant (the previous scheme) matched the old child's stamp whenever both occupants were first-time anchors. The id path needs none of this: ids are never reused, and the walk's monotonicity check (`parent_id < id`) rejects corrupted links.

### Evicted tasks are not adopted at their wake

The task maps are LRU hashes shared by every traced Tokio process, and an idle task's entry
is the first to go under capacity, since only a poll or a wake touches an entry. Without a
guard, the next wake of an evicted `LocalSet` task would reach `Shared::schedule` with no
entry and be registered as a child of the task current on the waking thread, the waker: a
mailbox task woken by request A's handler would then resolve A for every job it runs until
A's response, cross-endpoint. `tokio_task_slots` is a 2 MiB array of one-byte counts of the
live known tasks per slot, hashed from `(tgid, Header)`; being an array, it survives the
eviction of the task maps. Every registration that finds no counted entry takes a count:
`Cell::new`, the spawn hooks, either outcome of `Shared::schedule`, and the first poll of
a task with no entry (older than OBI's attach, or evicted), which also gives it a root
entry. The entry records that the task took a count (`counted`), and the release at
`Harness::complete` (or `raw::dealloc`) frees one only for such a task: an entry the anchor created on the spot may share its
slot with the task the count belongs to, and a task without an entry may have lost its
count to eviction, so neither decrements. The schedule hook consults the slot when the
entry is missing: a live slot is a wake and the task is re-registered with no parent (its
egresses orphan), an empty one is a spawn. A count, not a bit, so the release of a task
sharing a slot with a sleeping one cannot erase the sleeper's. A spawn sharing its slot
with a live task (one in 2 million per live task, about 1.4% of spawns at 30,000 live
tasks) loses its parent and nothing else, since it still takes its own count; a task
counted again after an eviction leaks its first count at its slot, which only withholds
parents there, and a saturated slot takes no count and releases none. The array is never
reset, so a host that stays above the task maps' capacity accumulates leaked counts over
OBI's uptime and withholds `spawn_local` parents at a growing share of slots: orphans,
never a wrong parent. One race undercounts instead: two tasks of one process sharing a
slot and changing its count at the same instant can lose one, after which the task left
uncounted can be adopted once evicted; it needs the collision and the coincidence
together. The
counts are bytes, so a change is one read-modify-write without the atomics the 5.8 floor
lacks; they are hashed, not keyed by pid, so a process exit does not purge them: a dead
process's unobserved deallocs leave a reused pid's tasks at those slots parentless until
their own dealloc. `TestRustTokioCurrentThread/mailbox_evicted` drives the sequence and
requires the re-registration (`origin=3`) in OBI's log.

### Closure symbols are excluded from path matching

In the v0 mangling scheme a closure demangles to the SAME path as its parent function (the simplified demangler drops the `NC` closure namespace), so a probe path like `…::set_current_task_id` would match the function's internal closure and post-demangle filtering is impossible; legacy closures demangle to a longer `…::{{closure}}` path and are filtered too, for symmetry. Probing a closure fires the handler with the closure's ABI (its PARM1 is `&Context`, not the task id), which would poison per-thread state. `isRustClosureSymbol` therefore filters on the RAW mangled form: legacy `$u7b$$u7b$closure$u7d$$u7d$` segments and v0 root `NC` elements (`_RNC…` / `__RNC…`).

### Context is refreshed at poll entry, not poll exit

`obi_ctx` (the pinned, OTEP-shared `traces_ctx_v1` map) is re-established for the running task on every poll **entry** and not at the exit of a top-level poll: deleting there would drop the context at the first `await` suspension of a still-in-flight request. Multi-thread workers are themselves blocking tasks (tokio launches each with `spawn_blocking`), so every user poll on a worker is nested, and its exit restores the worker's own task and refreshes for it, which resolves nothing and deletes the entry: on those threads the context lives for the duration of the poll, where the logs are written. The refresh resolves via the Header walk; in debug builds (where the Header walk misses) `obi_ctx` stays unset for Tokio tasks, a known coverage gap for external context readers, not for OBI's own parenting.

### The Tokio maps are gated to Tokio processes

The server-span-save path writes the Tokio maps only when `tokio_thread_state` is set for the thread. Non-Tokio servers hit this path constantly and must not pay for the extra writes or LRU churn. On the egress side a non-Tokio process pays exactly one `tokio_process` lookup, and a non-runtime thread of a Tokio process one `tokio_thread_state` lookup more.

### Probe attachment is mangling-aware

Symbols are resolved from the executable's `.symtab` by **demangled path**: Tokio's functions are generic (many monomorphized copies, all probed) and emitted under two mangling schemes, legacy (`_ZN…E`, `rustDemangle`) and v0 (`_R…`, `rustDemangleV0`; macOS adds `__R`). Both demanglers drop the generic arguments, so every copy demangles to the same path and a symbol matches only when its whole path equals the probe's. Nested helper functions (`Cell::new::new_header`, `Cell::new::check`, `Harness::poll_inner`) start with the parent's path but are different functions, inlined in release and out-of-line in debug builds; a prefix match attached the parent's probes to them in debug, which is why the match is exact. The scan runs only for executables detected as Rust; it streams the symbol tables the way the other uprobes are resolved (`FindExeSymbols`) and demangles only the symbols that name the `tokio` crate, so a large Rust binary without Tokio costs one walk of its symbol table. Two warnings guard the attachment: a path that resolves on some copies but not others ("partially resolved": a demangler gap or a stripped symbol), and copies that wanted a uretprobe but have no decodable return offsets (a toolchain change in the function epilogue or an instruction the decoder cannot read: the entry probe still attaches, the exit probe does not). Paths flagged `MayBeInlined` (`Id::next`) are exempt from both, since losing their copies in release is expected.

## Configuration

`capture.runtimes.rust.enabled` is the one knob, Config v2 only (Config v1 is frozen), default
`true`. Off, `UProbes()` carries no `self` key: no Tokio path is resolved, the process never gets
the `tokio_process` mark, and parents resolve through the generic thread-keyed path as before
this feature, with its work-stealing misattribution. `TestRustTokioRuntimeDisabled` pins that
path.

## Known Limitations

- **Release correlation depends on which Tokio internals the compiler keeps out of
  line.** `Harness::poll` survives because it is address-taken (the task vtable);
  `Cell::new` loses its copies for small futures; the three spawn hooks survive because
  each has one copy per scheduler with many callers, and the pooled-client correlation
  relies on the inlined poll frames keeping the request task current. All of that is
  compiler behavior, not an ABI guarantee: re-verify the symbol baseline above on
  toolchain bumps. The instrumenter's partial-resolution and return-offset warnings and
  the 4-build integration matrix are the tripwires; the debug id layer is the structural
  backstop. A `LocalSet` task whose `Cell::new` was inlined and whose Header address
  still carries a previous occupant's entry (its dealloc unobserved) keeps that stale
  lineage until the version or epoch guard refuses it, as every reused Header did before
  the hooks; `bind_inner` and `spawn_task` re-initialize it, `Shared::schedule` cannot
  tell a spawn from a wake and does not. The baseline covers cargo's default `release`
  and `dev` profiles; a custom profile that inlines more aggressively (`lto = "fat"`,
  `codegen-units = 1`) can drop further copies and is not measured.

- **Shared tasks: the in-flight window.** A long-lived task spawned under request N (a
  channel worker in an actor pattern, a pooled client's connection driver) records N's
  connection task as its lineage parent. The anchor-epoch guard and the untag at the
  response fail-close every egress the task makes AFTER N, but while N is still **in
  flight** the epoch legitimately matches (N's own handed-off job must resolve) and the
  runtime carries no signal distinguishing WHOSE job the task is serving: that information
  exists only inside the channel message or the pooled request. Jobs from other concurrent
  requests processed in that window inherit N's trace: same endpoint, same side, never
  cross-side. Measured across the 2026-10 runs: a few same-side piles per run at most
  (pooled client), none for the channel worker. Irreducible for lineage-based resolution;
  the designed fix is a channel send/recv bridge (pairing the sender's task identity with
  the received message), the first follow-up to this feature. `TestRustTokioProbeDiscrimination`'s
  `pooled_reuse` and `channel_handoff` subtests exercise both shapes adversarially, gate
  `contaminated == 0` strictly and log the same-side residual.

- **Outside the walk: OBI's same-host backend link is keyed by the client port alone.** A
  backend's inbound span takes the server's client context from `trace_map`, whose key drops
  the server address and port (`trace_key_from_conn`, a proxy port-forwarding accommodation;
  a traceparent header, where the tpinjector can inject one, overrides it). Linux hands one
  ephemeral source port to concurrent connections toward different destinations, so two
  pooled connections `127.0.0.1:59592 → :8093` and `→ :8094` share the key: the backend
  that reads first takes the other connection's context and its span joins the wrong trace,
  the second finds the entry consumed and orphans. The walk's own client span is unaffected.
  Measured 2026-11-05 (debug build, kernel 6.8 with header injection disabled by the FIONREAD
  misreport): 55 of 765 egress source ports served both backends, one cross-side backend
  span in 24 A/B runs. Generic OBI, on main as well. The suites count it as `stray`, log the
  trace and gate only `contaminated`. Running one backend process per port (the suite image)
  removes the sibling collision in `server_traces_aux`, whose key carries the server pid, not
  this one.

- **Fire-and-forget spawns orphan after the response.** A task spawned by a handler that
  performs its egress after the server has already answered resolves nothing: the anchor's
  trust window closed at the response. This is the price of closing the window; the
  alternative (a window that never closes) is the keep-alive misattribution class the
  untag was added to remove.

- **The attach window.** Probes attach per process in no fixed order, over a few
  milliseconds. A request served after `Harness::poll` attached but before
  `set_current_task_id` did anchors through the Header path even in a debug build
  (observed once: the backend's first request, 4 ms before its setter attached). The
  anchor is cleared at that request's response and the id path owns every anchor once
  the setter is attached, so the effect is bounded to requests in flight during the
  attach. Tasks spawned during the window record no parent state and orphan. A `LocalSet`
  task asleep across the attach whose first event is a wake by another task is registered
  at that wake as the waker's child (its slot is empty, so `Shared::schedule` reads the
  wake as a spawn): a one-off lineage under the epoch and version guards, same class as
  the shared-task in-flight window. A task polled at least once after the attach is
  counted at that poll and is not adopted later.

- **HTTP/2.** Inbound HTTP/2 anchors are epoch-guarded per request but the untag hooks the
  HTTP/1 response path only, so their trust window does not close at the response. HTTP/2
  egress has no per-request task identity at the connection level and fails closed by
  design. Both untested.

- **Threads of a Tokio process that never poll a task keep the thread-keyed resolution
  main uses.** The `block_on` driver of a multi-thread runtime (the workers run every task,
  the driving thread none) and the executor threads of a second async runtime in the same
  process resolve their own `server_traces[t_key]` entry, with its conflict rule: a second
  unanswered request on one such thread invalidates the first, so connections interleaved
  inside one thread orphan rather than mis-parent, while a request answered before the
  next arrives keeps the thread-keyed parent main would give it. No clone ancestry is
  followed for them.

- **`traces_ctx_v1` (`obi_ctx`) is not maintained for Tokio tasks in debug builds**, see
  [Context is refreshed at poll entry](#context-is-refreshed-at-poll-entry-not-poll-exit).

- **Map capacity.** The task maps are LRU hashes shared by every traced Tokio process, one
  30,000-entry cap for all of them, so one large process can evict another's entries. An
  evicted live task orphans its egresses, never misattributes: an evicted `LocalSet` task
  re-registers at its next wake with no parent, see
  [Evicted tasks are not adopted at their wake](#evicted-tasks-are-not-adopted-at-their-wake).
  With the 2 MiB slot array the five maps hold about 11.5 MiB of keys and values (4.4 MiB
  `tokio_task_state` at 152 B per entry, 3.7 MiB `tokio_task_id_state` at 128 B, 1.4 MiB
  `tokio_thread_state`, 0.1 MiB `tokio_process`), for which the kernel charges 19.3 MiB of
  memlock with its per-element headers and buckets (`bpftool map show`, Linux 6.8),
  preallocated when the tracer loads whether or not a Rust process exists. `capture.runtimes.rust.enabled:
  false` skips the probes and leaves the maps allocated.

- **Validated on arm64 only** until the x86 integration matrix runs: Linux 6.8 for the
  suites, 5.10.0 and 5.8 for the verifier; tokio 1.52.3 and 1.54.1; rust 1.99.0 (v0 mangling)
  and 1.96.0 (legacy mangling); cargo's default `release` and `dev` profiles.

- **Requires Tokio symbols in the binary (fully-stripped binaries are unsupported, and
  degrade to pre-Tokio behavior, not to fail-closed).** The probes attach to internal
  symbols resolved from `.symtab`; a fully-stripped binary attaches nothing, and OBI
  cannot even flag it (its Rust detection symbol is stripped too). With no probes the
  `tokio_process` gate is never set, so the process falls through to the **generic
  thread-identity resolvers**, which on a work-stealing runtime can misattribute, exactly
  what the gate exists to prevent. This is the one configuration where wrong parents remain
  possible; ship Rust binaries with symbols retained.

## Tests

The integration tests live in `internal/test/integration/red_test_rust_tokio_test.go` and
run against one container holding both the Rust server and its backend (OBI shares its pid
and network namespaces). The Rust app is built four ways, `CARGO_PROFILE={release,debug}`
× `RUST_LEG={v0,legacy}` (rust 1.99.0, whose stable default is the v0 `_R…` scheme since
Rust 1.97, and rust 1.96.0, the last toolchain emitting the legacy `_ZN…E` scheme by
default; legacy cannot be selected by flag on stable 1.97+), because the probes depend on
how rustc emits tokio and on which scheme names the copies; a change is green only on all
four. `TOKIO_VERSION` re-pins tokio for a one-off leg on another release, within what the
other locked crates accept (the actix stack in `Cargo.lock` needs tokio 1.51 or newer; a lower
release needs a lock resolved for it).

- `TestRustTokioContextPropagation` drives sequential requests and asserts at least one
  complete `server → client → backend` chain per pattern, then reads OBI's debug log and
  asserts the trust-window contract: anchors opened equal anchors closed (within the
  requests in flight), and in debug builds every anchor after the setter attached went
  through the id path.
- `TestRustTokioContextPropagationOBIFirst` runs the same checks with OBI attached before
  the app starts (the production order for an agent watching a new pod), and asserts from
  the log that both processes had their probes resolved before the first server span was
  saved.
- `TestRustTokioProbeDiscrimination` drives concurrent A/B load, each endpoint wired to its
  own backend path, and asserts per case cleanly-attributed chain floors AND zero
  misattribution in both detectable forms: `contaminated` (cross-side: a server span joined
  to the opposite endpoint's backend) and `piled` (same-side temporal: more same-side
  backend spans than server spans in one trace). The classifier identifies a span by its
  kernel span id (recovered from the "processing" child when OBI exported sub-spans), so a
  record OBI exported twice is not mistaken for a pile. Its `sync_threads` case drives the
  server's std-thread listener on port 8095, whose threads never poll a task, and requires
  the thread-keyed floor.
- `TestRustTokioCurrentThread` runs the same A/B discrimination against an actix-web server
  (`server-actix`): one current-thread runtime per worker with a `LocalSet`, the handler
  polled inside the per-connection dispatcher task, so tasks never migrate. Six shapes:
  direct egress, `tokio::spawn`, `spawn_local`, `spawn_local` → `tokio::spawn`, pooled
  client, and an evicted mailbox (`/evict-fill` parks 50,000 tasks so the task map evicts
  a long-lived `spawn_local` mailbox; its wake from inside a request's handler must not
  adopt that request). It is what caught the inlined `Cell::new` copies.
- `TestRustTokioRuntimeDisabled` runs the app with `capture.runtimes.rust.enabled: false`
  (Config v2) and checks that no Tokio path is resolved and no poll probe fires while the
  generic tracer still exports the server spans.

Every suite but the knob-off one also runs weaver's registry `live-check` on the exported
telemetry against OBI's schema registry and fails on a violation-level advisory.

Note on running the integration tests under a VM: after attach/detach cycles in a
long-lived Linux VM, the kernel's uprobe state can wedge; probes attach without error but
never fire (symptom: `tokio poll_future entry` count is 0 in OBI's log). Restarting the VM
clears it. Treat any run with a zero poll-probe count as invalid and re-run.
