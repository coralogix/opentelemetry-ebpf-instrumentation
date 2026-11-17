// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_key.h>

// The task that was being polled when this thread was cloned, or the cloning thread's own
// birth when it was polling none (devdoc "Threads born inside a task inherit its lineage").
typedef struct tokio_thread_birth {
    u64 task;    // Header of the task
    u64 version; // its incarnation stamp at the clone: a reused Header never matches
    u64 epoch;   // its anchor_epoch at the clone: a re-anchored task never matches
    u32 tgid;    // OBI-view pid, the process half of the task key
    u8 _pad[4];
} tokio_thread_birth_t;

// Keyed like clone_map: the clone hook knows the child only by its namespaced tid. Written
// at sys_clone return, deleted at the thread's exit; a stale entry never resolves (version).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t); // the child thread
    __type(value, tokio_thread_birth_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_thread_birth SEC(".maps");
