// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Key of the per-task Tokio maps. A task identity only means something inside one
// process: a Header pointer is a heap address that can coincide across address spaces,
// and tokio::task::Id is a per-process counter that starts at 1 in every process. Without
// the tgid, two instrumented Tokio processes would share entries and resolve each other's
// inbound requests as parents.
typedef struct tokio_task_key {
    u32 tgid; // OBI-view pid (tokio_thread_state_t.tgid), not the host tgid
    u32 _pad;
    u64 id; // Header pointer (tokio_task_state) or task Id (tokio_task_id_state)
} tokio_task_key_t;

static __always_inline tokio_task_key_t tokio_task_key(u32 tgid, u64 id) {
    return (tokio_task_key_t){.tgid = tgid, .id = id};
}
