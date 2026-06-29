// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct tokio_thread_state {
    u64 current_task; // RawTask Header pointer of the task currently being polled (0 = none)
} tokio_thread_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, tokio_thread_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_thread_state SEC(".maps");

// Per-thread "last confirmed inbound connection" — written when a task is
// poll-refreshed with a confirmed inbound conn (pid_tid_to_conn guard passes).
// Used as fallback in find_tokio_parent_trace_for_thread when the ancestry walk
// fails because the reqwest/hyper connection pool task predates OBI or sits in
// a structurally disconnected task subtree (e.g., actix-web + reqwest client).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // pid_tgid
    __type(value, connection_info_part_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_thread_inbound_conn SEC(".maps");

// Per-process last-seen inbound connection (keyed by tgid only).
// Written by server_or_client_trace when a server HTTP span is saved.
// Read as a last-resort fallback in find_tokio_parent_trace_for_thread for
// tasks on tokio blocking-pool threads (spawn_blocking), which run on a
// different OS thread than the handler that detected the inbound request,
// making both the ancestry walk and the thread-level fallback fail.
// Caveat: last-write-wins — context may be misattributed if multiple clients
// concurrently hit spawn_blocking endpoints on the same process.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // tgid
    __type(value, connection_info_part_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_process_inbound_conn SEC(".maps");
