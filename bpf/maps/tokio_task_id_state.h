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

// Per-task state keyed by the tokio task Id (the runtime's monotone u64 counter,
// tokio::runtime::task::Id), NOT by the Header pointer.
//
// This is the DEBUG-build complement to tokio_task_state (Header-keyed): in debug builds
// the per-request task is never the Harness::poll-derived current_task at the egress (it
// collapses to a coarse worker-root), but tokio's own TLS — maintained via
// tokio::runtime::context::set_current_task_id, which fires as a symbol only in debug —
// still knows the running task's Id. The id-keyed lineage lets debug egresses resolve
// where the Header walk structurally cannot. In release the setter's call sites are
// inlined (never fires) and Id::next resolves no usable copy, so this map stays empty and
// the id path is structurally inert — the Header walk remains the release mechanism.
//
// Task Ids are never reused (monotone counter), so unlike the Header map there is no
// pointer-reuse hazard class: no version counters, no parent_version validation. Entries
// are deleted when the paired Header deallocs (see obi_uprobe_tokio_dealloc), which is
// also what fail-closes the pooled-driver-reuse hazard: a driver task's lineage points at
// the request that first spawned it, and once that request's task deallocs the stale
// lineage resolves to nothing instead of to the wrong request.
typedef struct tokio_task_id_state {
    u64 parent_id;               // task Id of the spawning task (0 = root/unknown)
    u64 parent_epoch;            // the parent's anchor_epoch captured at spawn time. The
                                 // walk follows the link only while it still matches:
                                 // a lineage created during request N must die when its
                                 // anchor moves on to request N+1. Without this, a task
                                 // spawned lazily INSIDE a handler but living beyond the
                                 // request (an actor/worker task) keeps a parent chain to
                                 // a still-alive, re-anchored conn task and would resolve
                                 // whatever request that anchor CURRENTLY serves — a
                                 // cross-request leak the dealloc fail-close cannot catch
                                 // (the anchor never died). Id-path twin of the Header
                                 // path's parent_version.
    u64 anchor_epoch;            // bumped every time this task is (re-)anchored to an
                                 // inbound request (tokio_tag_inbound_conn). 0 = never
                                 // anchored (intermediate lineage nodes stay 0 forever,
                                 // so links to them always match).
    connection_info_part_t conn; // inbound server connection this task lineage belongs to
    tp_info_pid_t tp;            // SNAPSHOT of the owning server trace, taken at anchor
                                 // time (the same tp written to server_traces_aux at that
                                 // instant). Set ONLY on the anchored task — never copied
                                 // to descendants: an inherited copy on a long-lived task
                                 // (hyper conn driver, app worker) would outlive its
                                 // request and resolve LATER requests' egresses to the old
                                 // trace (a same-side temporal misattribution invisible to
                                 // A/B testing). The egress walk climbs the parent_id
                                 // chain to the anchor instead. Resolving from the
                                 // snapshot rather than a late server_traces_aux[conn]
                                 // lookup closes the connection-key overwrite class
                                 // (keep-alive reuse / client ephemeral-port reuse
                                 // remapping the aux entry before a slow egress resolves
                                 // it). The Header-path anchor carries the same snapshot
                                 // (see tokio_task_state.h — the historical "idea 6"
                                 // objection is obsolete there). A NAIVE Header snapshot
                                 // without re-init/dealloc/atomic-publish would be unsafe
                                 // (pointer reuse — the historical "idea 6" failure); task
                                 // Ids are monotone and never reused.
    u8 tp_valid;                 // 1 if tp holds a snapshot
    u8 conn_valid;               // 1 if conn was populated from an inbound request
    u8 conn_shared;              // 1 if anchored to >1 distinct inbound request -> shared/
                                 // long-lived task, conn ambiguous, never resolve/inherit
    u8 _pad[5];
} tokio_task_id_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tokio_task_key_t); // {tgid, tokio task Id} — Ids are a per-process monotone
                                   // counter, never reused within a process
    __type(value, tokio_task_id_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_id_state SEC(".maps");
