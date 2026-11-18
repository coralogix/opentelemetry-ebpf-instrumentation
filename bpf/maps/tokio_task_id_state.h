// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tokio_task_key.h>
#include <common/tp_info.h>

// Debug-build twin of tokio_task_state keyed by tokio task id (devdoc "Two complementary
// task-identity mechanisms"); release never populates it. Ids are never reused, so there is
// no incarnation stamp; an entry dies with its paired Header at task end.
typedef struct tokio_task_id_state {
    u64 parent_id;               // spawning task's id, 0 = root or unknown
    u64 parent_epoch;            // parent's anchor_epoch at spawn; followed only while it matches
    u64 anchor_epoch;            // bumped at every (re-)anchor; 0 = never anchored
    connection_info_part_t conn; // inbound connection this task was anchored to
    tp_info_pid_t tp;            // owning server trace, snapshotted at anchor time; never copied
                                 // to descendants, the walks resolve from nothing else
    u8 tp_valid;                 // 1 if tp holds a snapshot
    u8 conn_valid;               // 1 if conn was set by an inbound request
    u8 conn_shared;              // 1 if anchored to more than one connection: never trusted
    u8 _pad[5];
} tokio_task_id_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tokio_task_key_t); // {tgid, task id}
    __type(value, tokio_task_id_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_id_state SEC(".maps");
