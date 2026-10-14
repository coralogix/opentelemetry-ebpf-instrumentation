// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct tokio_thread_state {
    u64 current_task;   // RawTask Header pointer of the task currently being polled (0 = none)
    u64 current_id;     // tokio task Id currently running on this thread, mirrored from the
                        // runtime's own TLS via set_current_task_id (debug builds only — the
                        // setter's call sites are inlined in release). 0 = none. Reset to 0 at
                        // every poll entry so it is trusted only when the setter re-set it
                        // WITHIN the current poll: this keeps the id path provably inert under
                        // partial inlining (a release toolchain that inlines only some call
                        // sites could otherwise leave a stale id behind — a wrong parent
                        // hazard, worse than none).
    u64 pending_new_id; // Id::next result awaiting its Cell::new pairing on this thread
                        // (task creation calls Id::next then Cell::new back-to-back on the
                        // spawning thread). 0 = none. Consumed by the FIRST Cell::new after
                        // Id::next; a mispairing therefore degrades to a missing id (orphan,
                        // fail-closed), never a wrong one.
    u64 prev_task;      // current_task of the enclosing poll when polls nest on this thread
                        // (one level, e.g. a nested runtime driven from inside a
                        // spawn_blocking closure); restored by the inner poll's exit. Relies
                        // on that exit probe firing: a poll copy without a RET would leave
                        // the outer task current on this thread after the outer poll ends.
    u32 tgid;           // OBI-view pid of the process (valid_pid()'s return at the probe):
                        // the process half of every tokio map key, so the Go side can purge
                        // a dead process by the pid it knows (host tgid in init pid-namespace
                        // mode, the namespace pid in pod mode).
    u32 _pad;
} tokio_thread_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, tokio_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_thread_state SEC(".maps");

// Presence flag set once per process the first time any of its threads polls a
// Tokio task. Read in resolve_parent_trace to make Tokio parent lookup FAIL
// CLOSED: when the ancestry walk finds no owning request, a Tokio process must
// NOT fall through to the generic clone_map thread-ancestry walk. Tokio's worker
// and blocking-pool threads are shared across requests, so thread ancestry does
// not imply request lineage — the generic walk would attribute the egress to an
// unrelated request (misattribution). Stores only a flag (no connection), so it
// cannot itself misattribute.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);  // tgid
    __type(value, u8); // 1 = this process runs Tokio
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_process SEC(".maps");
