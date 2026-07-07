# Rust Tokio Context Propagation

This document describes the architecture and implementation of context propagation for Rust applications built on the [Tokio](https://tokio.rs) async runtime.
It extends the existing context propagation mechanisms documented in [context-propagation.md](context-propagation.md) and follows the same design shape as [python-asyncio-context-propagation.md](python-asyncio-context-propagation.md).

## Table of Contents

- [Current State](#current-state)
- [Architecture](#architecture)
- [Runtime Model](#runtime-model)
- [Probe Points](#probe-points)
- [Parent Lookup](#parent-lookup)
- [Implementation Details](#implementation-details)
- [Known Limitations](#known-limitations)

## Current State

| Execution pattern | Tokio runtime behavior | OBI correlation path |
|-------------------|------------------------|----------------------|
| `await` in the handler task on a current-thread runtime (e.g. actix-web) | Each worker owns a single-threaded runtime, so a task never migrates between OS threads | Thread-local `pid_tid_to_conn` already resolves the request; the Tokio ancestry walk is not strictly required, but `Cell::new` still records lineage |
| `tokio::spawn` on a multi-thread runtime (e.g. Axum) | The spawned task is enqueued in the global scheduler and may be **stolen by a different worker thread** before it runs | The child task inherits the parent's request connection at `Cell::new`; the egress walk resolves the request from `tokio_task_state` regardless of which thread runs the task |
| Nested `tokio::spawn` (depth ≥ 2) | Each spawn is a fresh task; each may migrate independently | `find_tokio_parent_trace` walks the stored parent chain (up to 8 levels) until it finds the task that owns the inbound request |
| `tokio::task::spawn_blocking` | The closure runs on a dedicated **blocking-pool OS thread**, separate from the async workers | The blocking task's cell is allocated by `Cell::new` on the handler thread, so it inherits the handler's connection; the egress walk then resolves it at depth 0 |

## Architecture

### Why thread-only correlation is not enough

OBI normally assumes that work running on the same OS thread belongs to the same logical request: it keys the in-flight request connection by thread id in `pid_tid_to_conn`. That assumption holds for thread-per-request servers and even for current-thread async runtimes (where a worker owns one runtime), but it breaks for the Tokio multi-thread runtime:

- one runtime drives many requests across a shared pool of worker threads,
- a task created on the handler's thread can be **stolen and resumed on a different worker** before it makes its outgoing call,
- `spawn_blocking` moves work onto a blocking-pool thread that never ran the
  handler at all.

In each case the outgoing client syscall happens on a thread whose `pid_tid_to_conn` either belongs to a *different* in-flight request or is empty.
To recover the correct parent trace, the tracer needs the current logical Tokio **task** rather than only the current OS thread.

### What the Tokio implementation adds

The implementation introduces three pieces of Tokio-specific BPF state, keyed by the task's `Header` pointer (a stable heap address for the task's lifetime):

1. **Per-thread state** in `tokio_thread_state`
   - tracks the `Header*` of the task currently being polled on this OS thread (`current_task`),
   - plus two auxiliary fallback maps: `tokio_thread_inbound_conn` (last inbound connection confirmed on this thread) and `tokio_process_inbound_conn` (last inbound connection seen anywhere in the process, keyed by tgid).

2. **Per-task state** in `tokio_task_state`
   - stores the parent task pointer and the parent's version captured at spawn time,
   - stores an ephemeral partial connection key (`connection_info_part_t`, `conn` + `conn_valid`) identifying the server-side request the task lineage belongs to,
   - stores a monotonically increasing `version` for `Header*` reuse protection.

3. **Context refresh** through the shared `obi_ctx` / `traces_ctx_v1` map
   - re-established on every poll entry so external readers and in-process context lookups follow the task across thread migration.

The end result is the same two-stage lookup used by the Python async path:

1. resolve the current logical task (from `tokio_thread_state.current_task`),
2. walk task ancestry until finding the task that owns the inbound request connection, then resolve the parent span through `server_traces_aux` — exactly the generic parent-trace flow used elsewhere in the tracer.

## Runtime Model

The design depends on a few Tokio behaviors:

1. Every task poll dispatches through the task's vtable to the monomorphized free fn `tokio::runtime::task::raw::poll::<T,S>`. That function's address is stored in the vtable, so it cannot be inlined and is reached via an indirect call on every poll — for every task type and every scheduler (multi-thread workers, current-thread, and the blocking pool) — in both debug and release.
2. Every task-creation path allocates the task's cell through `tokio::runtime::task::core::Cell::<T,S>::new` (multi-thread scheduler, current-thread scheduler, and the blocking pool all bottom out here). It runs synchronously on the spawning thread while the spawning task is still "current", so the new task pointer and its parent are simultaneously observable. `Cell` is `#[repr(C)]` with `header` first and `Cell::new` returns `Box<Cell>`, so the returned pointer is the task `Header`.
3. `spawn_blocking`'s task is *also* allocated through `Cell::new`, synchronously on the handler thread while the handler is still "current". So the blocking task inherits the handler's request connection through the same `Cell::new` path — no dedicated `spawn_blocking` probe is needed.

Tokio is **statically linked** into the application binary, so all probes target the executable itself (`SEC("uprobe/self:...")`) rather than a shared library.

## Probe Points

The implementation is built around three BPF programs. Because Tokio's internal symbols are generic and monomorphized — and are emitted under two different Rust mangling schemes — the Go-side instrumenter attaches each program to *every* matching symbol via demangled-prefix matching (`FindExeSymbolsByPrefix`).

### `raw::poll` (poll entry/exit) — `tokio_poll`

`tokio::runtime::task::raw::poll::<T,S>` fires when the executor polls a task. It is the function whose address sits in each task's vtable, reached via the scheduler's indirect call.

- **Entry** (`obi_uprobe_tokio_poll`): records `current_task = PARM1` (the `Header*`) in `tokio_thread_state`, lazily (re)registers the task's inbound connection when this thread is serving a confirmed inbound request, and refreshes `obi_ctx` for the task now running here.
- **Exit** (`obi_uretprobe_tokio_poll`): clears `current_task`. Each `raw::poll` copy tail-calls the harness (`br`, no `ret`), so in practice the uretprobe is skipped; `current_task` is overwritten on the next entry and `obi_ctx` is managed at entry, so this is safe.

We probe `raw::poll` rather than the thin `RawTask::poll` thunk that performs the indirect call: that thunk (`ldr vtable; ldr vtable.poll; br`) is inlined into the scheduler's `run_task` in release, so a probe on it never fires on multi-thread workers in release — which made the feature inert in release multi-thread. The vtable target `raw::poll` cannot be inlined (its address is taken), so it is the correct universal probe point; its monomorphized copies are attached via prefix matching. `harness::poll_future` is also not probed (it would double-fire). PARM1 is the `Header*` in all cases.

### `Cell::new` (task creation) — `tokio_cell_new`

Fires when a new task's cell is allocated. Every task-creation path funnels through
`tokio::runtime::task::core::Cell::<T,S>::new` — the leaf constructor called by
`new_task` for the multi-thread scheduler (`tokio::spawn`), the current-thread
scheduler (`spawn_local`), and the blocking pool. It is the single universal,
release-stable task-creation point.

We probe `Cell::new` as a **uretprobe** (`obi_uretprobe_tokio_cell_new`) and read the new task's `Header` from the **return value** (`PT_REGS_RC`). `Cell::new` returns `Box<Cell<T,S>>`, and `Cell` is `#[repr(C)]` with `header: Header` as its first field, so the returned pointer *is* the task `Header` pointer used everywhere else — no argument-slot or pre-vs-post-construction ambiguity. The handler records the new task's parent (`current_task` on the spawning thread, unchanged) and the connection it should inherit. See [Request ownership is captured at task creation time](#request-ownership-is-captured-at-task-creation-time).

`Cell::new` is chosen over the `bind` functions because those are asymmetric across schedulers: `OwnedTasks` factors out a `bind_inner` that receives the built `Task<S>` (the `Header`), but `LocalOwnedTasks::bind` has no such helper and its argument at entry is the raw future, not the `Header`. `Cell::new` sidesteps that entirely by reading the finished cell from the return, and — unlike the intermediate `new_task` / `RawTask::new`, which are inlined away in release — it survives (it does the heap allocation). It also covers **blocking-pool tasks**: `spawn_blocking`'s task cell is allocated by `Cell::new` on the handler thread while the handler is "current", so the blocking task inherits the handler's connection through the ordinary parent-inheritance path. No separate `spawn_blocking` probe is needed (an earlier revision had a dedicated `pool::spawn_blocking` uretprobe; `Cell::new` made it redundant and it was removed).

## Parent Lookup

When a Tokio client request needs a trace parent (at egress, via `find_tokio_parent_trace_for_thread` in `trace_parent.h`), lookup happens in two phases plus fallbacks.

### Phase 1: resolve the current logical task

Read `tokio_thread_state[pid_tgid].current_task`. If the thread is actively polling a task, that pointer is the entry point for the ancestry walk.

Because `raw::poll` (the vtable target) fires on every poll for every scheduler — including the blocking pool — `current_task` is set on blocking-pool threads in both debug and release, so `spawn_blocking` tasks resolve through the normal walk.
The fallbacks below remain for tasks that predate OBI or sit in a structurally disconnected subtree. (The lookup also does not return early when `current_task` is unset, so the fallbacks stay reachable.)

### Phase 2: walk task ancestry until a request owner is found

`find_tokio_parent_trace(task_id)` (in `tokio_task.h`) walks the `tokio_task_state` parent chain, bounded to `k_max_tokio_task_depth = 8` levels (reqwest + hyper interpose internal tasks between the handler and the `tcp_sendmsg` site). For each task it checks `conn_valid`; when set, it looks up `server_traces_aux[conn]` and returns the owning trace. The walk:

- stops on a missing parent or a self-referential link (pointer-reuse guard),
- rejects a parent whose current `version` no longer matches the `parent_version` recorded at spawn time (LRU-eviction guard, see [Task pointer reuse is versioned](#task-pointer-reuse-is-versioned)).

### Fallbacks

When the walk fails (e.g. a connection-pool driver task that predates OBI, or a structurally disconnected subtree), two fallbacks recover the request:

1. **Thread-level** (`tokio_thread_inbound_conn[pid_tgid]`) — the last inbound connection confirmed on *this* thread. Used when the handler thread is still the egress thread but the task lineage is broken.
2. **Process-level** (`tokio_process_inbound_conn[tgid]`) — the last inbound connection seen anywhere in the process. Last resort for `spawn_blocking` tasks whose blocking-pool thread never ran the handler. This is last-write-wins and therefore racy under concurrency (see [Known Limitations](#known-limitations)).

## Implementation Details

### Request ownership is captured at task creation time

`obi_uretprobe_tokio_cell_new` stores the request connection with a parent-first rule, mirroring `python.c:_asyncio_Task___init__`:

1. if the spawning (parent) task already has `conn_valid`, the child **inherits** that connection directly — this propagates the inbound request down the task lineage,
2. otherwise it falls back to the current thread's `pid_tid_to_conn` — covering the first task spawned directly inside a handler.

Preferring the parent matters because `tokio_task_state` is request-scoped while `pid_tid_to_conn` is only thread-scoped: once child tasks interleave on a worker, the thread-local connection can already belong to a different in-flight request.

The handler task's own connection is set when the inbound server span is saved (`trace_lifecycle.h`). If the handler task predates OBI and was never seen by `Cell::new`, that path **lazily registers** it in `tokio_task_state` so the ancestry walk (including from blocking-pool tasks it spawned) can still find it.

### The inbound-vs-outbound connection guard

`pid_tid_to_conn` holds whatever connection most recently touched the thread — which may be an *outgoing* `connect()` rather than the inbound request.
Writing an outbound connection as an `FD_SERVER` key would poison `tokio_task_state` and make every later `server_traces_aux` lookup miss.

The poll-entry refresh and `Cell::new` therefore only adopt a thread connection when `d_port != orig_dport`. For an accepted inbound connection, `sort_connection_info` swaps the ports so `d_port` becomes the local server port (≠ the client's remote ephemeral `orig_dport`); for an outgoing connection both are the remote backend port and are equal. The inequality distinguishes the two.

### Connection refresh only fills, never clobbers

The poll-entry refresh writes a task's connection only when it does **not** already own one (`!existing || !existing->conn_valid`). A migrated task can be polled on a worker whose `pid_tid_to_conn` holds an unrelated request's connection; refreshing an already-correct (inherited) connection there would misattribute it. The refresh exists only to lazily register pre-OBI / pool tasks that have no connection yet, so it preserves the existing `version` rather than bumping it.

### Context is refreshed at poll entry, not poll exit

`obi_ctx` (the pinned, OTEP-shared `traces_ctx_v1` map) is re-established for the running task on every poll **entry** (`tokio_refresh_obi_ctx`), and deliberately not touched on poll exit:

- **Release safety** — each `raw::poll` copy tail-calls the harness with no `RET`, so the poll uretprobe may be skipped. An exit-time `obi_ctx__del` would never run. The entry uprobe always fires, so entry-time refresh is reliable.
- **No flicker** — deleting `obi_ctx` on every poll exit would drop the context at the first `await` suspension of a still-in-flight request. Refreshing to the task's own owning trace on each entry keeps the context correct for the whole request, follows a migrated task, and overwrites any stale context left by a different task that previously ran on this thread.

### Task pointer reuse is versioned

Tokio can reuse the same `Header*` address for a later task. To prevent a stale parent link from resolving to the wrong task, each `tokio_task_state` carries a `version` counter, bumped on detected pointer reuse.
A child records its parent's version at spawn time (`parent_version`); the ancestry walk aborts the link if the parent's current version no longer matches.
Only a positive mismatch aborts — an unset (`0`) `parent_version` is trusted, to avoid false-aborting a real but unversioned lineage.

### The Tokio maps are gated to Tokio processes

`server_or_client_trace` (the path every HTTP server request reaches) only writes the Tokio-specific maps when `tokio_thread_state` is set for the thread — i.e. this is actually a Tokio process.
Non-Tokio servers (Go, Java, Python, nginx, …) hit this path constantly and must not pay for the extra writes or LRU churn.

### Probe attachment is mangling-aware

The userspace instrumenter resolves Tokio symbols from the executable's own symbol table and matches them by **demangled prefix**, because:

- Tokio's `poll` and `Cell::new` symbols are **generic** and emitted as many monomorphized copies (one per type instantiation); all copies must be probed.
- Rust emits symbols under two mangling schemes — **legacy** (`_ZN…E`, decoded by `rustDemangle`) and **v0** (`_R…`, decoded by `rustDemangleV0`; macOS adds a leading `__R`). `FindExeSymbolsByPrefix` demangles each symbol and matches the configured prefixes against the result, so both schemes resolve to the same probe set. Build-hash suffixes (`17h<hash>`) and `$LT$…$GT$` generic encodings are stripped during demangling.

## Known Limitations

- **Keep-alive connection-overwrite tail.** Under heavy concurrent load on a reused keep-alive connection, the connection-keyed `server_traces_aux` entry can be overwritten before egress resolves it, dropping or occasionally misattributing a small fraction of chains. This is a connection-level limitation independent of the Tokio task-walk (it affects the generic path too).

- **Requires Tokio symbols in the binary (fully-stripped binaries are unsupported).** The probes attach to internal, non-exported symbols (`tokio::runtime::task::raw::poll`, `Cell::new`) resolved from `.symtab` by demangled-prefix matching. A fully-stripped release binary has no `.symtab`, so nothing attaches and Tokio propagation is **silently unavailable** — and OBI cannot even flag it, because its "is this Rust?" detection keys on the `rust_panic` symbol, which the same strip removes. There is no runtime recovery; ship with symbols retained. (A *partial* resolution — some monomorphized copies present, others not — is surfaced as a `Warn` by the instrumenter; only the fully-stripped case is undetectable.)

All Tokio patterns — `await`, `tokio::spawn` with work-stealing, nested spawn, and `spawn_blocking` — are correct in **both debug and release**, including under concurrency, because `raw::poll` (the vtable target) fires on every poll for every scheduler so each task carries its own request's connection by per-task identity.

> Note: an earlier revision probed `RawTask::poll`, the thin thunk that the
> optimiser inlines in release. That left the task-walk inert on multi-thread
> workers and the blocking pool in release, so release `spawn_blocking` under
> concurrency mis-/under-attributed (~10–50%). Re-targeting the probe to the
> vtable function `raw::poll` (which cannot be inlined) resolved this — see the
> `tokio_poll` probe description above.

The integration tests cover both: `TestRustTokioContextPropagation` asserts at least one complete `server -> backend` chain per pattern, and `TestRustTokioProbeDiscrimination` drives concurrent A/B `spawn_blocking` load and requires many cleanly-attributed chains — a test that fails on the generic path alone and passes only when the Tokio probes correlate.
