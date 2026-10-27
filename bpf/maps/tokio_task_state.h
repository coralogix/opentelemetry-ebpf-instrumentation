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

typedef struct tokio_task_state {
    u64 parent;                  // Header of the spawning task, 0 = root or unknown
    u64 parent_version;          // parent's incarnation stamp at spawn; the link is followed
                                 // only while it still matches (a recycled or re-created
                                 // parent Header). 0 = parent not registered: never followed
    u64 version;                 // incarnation stamp of this occupant of the Header address
                                 // (creation time, tokio_task_incarnation); never 0
    u64 task_id;                 // paired tokio id from Id::next, 0 = unknown; lets dealloc
                                 // delete the id-keyed twin
    u64 anchor_epoch;            // bumped at every (re-)anchor; 0 = never anchored. A
                                 // descendant that outlives its request keeps a link to a
                                 // still-alive, re-anchored connection task; the walk
                                 // rejects it once this epoch has moved on
    u64 parent_epoch;            // parent's anchor_epoch at spawn; see anchor_epoch
    connection_info_part_t conn; // inbound connection this task was anchored to
    tp_info_pid_t tp;            // owning server trace, snapshotted at anchor time: the walks
                                 // resolve from it and never from server_traces_aux, which
                                 // is last-write-wins per connection key
    u8 tp_valid;                 // 1 if tp holds a snapshot
    u8 conn_valid;               // 1 if conn was set by an inbound request
    u8 conn_shared;              // 1 if anchored to more than one connection: never trusted
    u8 _pad[5];
} tokio_task_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tokio_task_key_t); // {tgid, task Header pointer}
    __type(value, tokio_task_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_state SEC(".maps");
