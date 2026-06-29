// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct tokio_task_state {
    u64 parent;                  // task pointer of the spawning task (0 if root/unknown)
    u64 parent_version;          // parent's version captured at spawn time; the ancestry walk
                                 // rejects a parent whose current version no longer matches,
                                 // catching a reused/evicted parent pointer, 0 = unknown
                                 // (not captured) -> not validated.
    u64 version;                 // incremented on task-pointer reuse detection
    connection_info_part_t conn; // inbound server connection this task lineage belongs to
    u8 conn_valid;               // 1 if conn has been populated from an inbound request
    u8 _pad[7];
} tokio_task_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // Tokio task Header pointer (RawTask/Header*)
    __type(value, tokio_task_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_state SEC(".maps");
