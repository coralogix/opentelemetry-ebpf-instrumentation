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
    u64 parent;                  // task pointer of the spawning task (0 if root/unknown)
    u64 parent_version;          // parent's incarnation stamp captured at spawn time; the
                                 // ancestry walk follows the link only while the parent's
                                 // current version still matches, which rejects a recycled
                                 // or evicted-and-recreated parent pointer. 0 = parent not
                                 // registered at spawn -> link never followed.
    u64 version;                 // incarnation stamp of this occupant of the Header address
                                 // (monotonic creation time, tokio_task_incarnation); never 0
    u64 task_id;                 // this task's tokio Id (paired from Id::next at creation;
                                 // 0 = unknown). Used at dealloc to delete the id-keyed
                                 // twin entry in tokio_task_id_state, so a completed task's
                                 // id lineage cannot resolve for a later request (the
                                 // pooled-driver-reuse fail-close).
    u64 anchor_epoch;            // bumped each time this task is (re-)anchored to an inbound
                                 // request (tokio_tag_inbound_conn). 0 = never anchored.
                                 // Twin of the id path's anchor_epoch: a descendant that
                                 // outlives its request (a pooled hyper conn driver, an
                                 // actor/worker task) keeps a parent chain to a STILL-ALIVE
                                 // keep-alive conn task that is re-anchored last-write-wins
                                 // (its conn KEY is unchanged, so conn_shared never trips);
                                 // the walk rejects the link once this epoch has advanced,
                                 // failing closed instead of resolving whatever request the
                                 // anchor now serves.
    u64 parent_epoch;            // the parent's anchor_epoch captured at spawn; the walk
                                 // follows the parent link only while it still matches.
    connection_info_part_t conn; // inbound server connection this task lineage belongs to
    tp_info_pid_t tp;            // SNAPSHOT of the owning server trace, taken at anchor time
                                 // (the same tp written to server_traces_aux at that instant).
                                 // Resolving from the snapshot instead of a late
                                 // server_traces_aux[conn] lookup closes the keep-alive
                                 // overwrite tail: two requests on one inbound connection
                                 // share the conn KEY, so the aux entry is last-write-wins
                                 // and a slightly-late egress of request N resolves request
                                 // N+1's trace (measured ~1/300 per endpoint in release).
                                 // The historical objection to a Header-keyed snapshot
                                 // ("idea 6": a stale snapshot resurrected by pointer reuse)
                                 // is obsolete: Cell::new re-initializes a reused entry
                                 // (tp_valid=0), raw::dealloc deletes it, and the anchor
                                 // writes are copy-modify-publish (atomic for readers).
    u8 tp_valid;                 // 1 if tp holds a snapshot
    u8 conn_valid;               // 1 if conn has been populated from an inbound request
    u8 conn_shared;              // 1 if this task was anchored to >1 distinct inbound request
                                 // -> it is a shared/long-lived task, not a per-request handler,
                                 // so its conn is ambiguous (last-write-wins) and must NOT be used
                                 // to resolve or inherit a trace (fail closed instead).
    u8 _pad[5];
} tokio_task_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tokio_task_key_t); // {tgid, Tokio task Header pointer (RawTask/Header*)}
    __type(value, tokio_task_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_state SEC(".maps");
