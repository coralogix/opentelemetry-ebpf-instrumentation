// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Header addresses and tokio::task::Id both repeat across processes (devdoc "Keys are
// (OBI-view pid, identity) and state dies with the process").
typedef struct tokio_task_key {
    u32 tgid; // OBI-view pid (tokio_thread_state_t.tgid), not the host tgid
    u32 _pad;
    u64 id; // Header pointer (tokio_task_state) or task Id (tokio_task_id_state)
} tokio_task_key_t;

static __always_inline tokio_task_key_t tokio_task_key(u32 tgid, u64 id) {
    return (tokio_task_key_t){.tgid = tgid, .id = id};
}
