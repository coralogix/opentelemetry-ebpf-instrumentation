// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct tokio_thread_state {
    u64 current_task;   // Header of the task being polled, 0 = none
    u64 current_id;     // tokio task id from set_current_task_id, debug builds only; reset to
                        // 0 at every poll entry so it is trusted only when set within the
                        // current poll (a stale id under partial inlining never resolves)
    u64 pending_new_id; // Id::next result awaiting its Cell::new on this thread, 0 = none;
                        // consumed once, so a mispairing degrades to a missing id
    u64 prev_task;      // enclosing task when polls nest (one level), restored at exit
    u32 tgid;           // OBI-view pid: the process half of every tokio map key, so the Go
                        // side can purge a dead process by the pid it knows
    u32 _pad;
} tokio_thread_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, tokio_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_thread_state SEC(".maps");

// Set once per process on its first task poll. find_parent_trace resolves a Tokio process
// only through the task walks: worker and blocking-pool threads are shared across requests,
// so the generic thread-ancestry resolvers would misattribute.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);  // tgid
    __type(value, u8); // 1 = this process runs Tokio
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_process SEC(".maps");
