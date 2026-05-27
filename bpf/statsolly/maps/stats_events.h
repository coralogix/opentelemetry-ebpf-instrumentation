// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, OBI_PIN_INTERNAL);
} stats_events SEC(".maps");

static volatile u64 __stats_submission_count = 0;

static __always_inline long stats_events_flags() {
    const u64 avail_data = bpf_ringbuf_query(&stats_events, BPF_RB_AVAIL_DATA);
    const u64 n = __stats_submission_count;
    __sync_fetch_and_add(&__stats_submission_count, 1);
    if (n % 1000 == 0) {
        bpf_printk("stats_events: submissions=%llu avail_data=%llu", n, avail_data);
    }
    return avail_data >= 4096 ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

