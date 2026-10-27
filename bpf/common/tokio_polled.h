// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/tokio_polled_headers.h>

// Multiplicative hash of (tgid, Header) into a slot. The tgid folds in because Header
// addresses alias across processes; the multiply spreads the address bits the cell
// alignment leaves at zero.
static __always_inline u32 tokio_polled_slot(u32 tgid, u64 header) {
    const u64 mixed = (header ^ ((u64)tgid << 32)) * 0x9E3779B97F4A7C15ULL;
    return (u32)(mixed >> (64 - k_tokio_polled_slots_shift));
}

static __always_inline u8 *tokio_polled_lane(u32 tgid, u64 header) {
    const u32 slot = tokio_polled_slot(tgid, header);
    const u32 word = slot / k_tokio_polled_lanes;
    tokio_polled_word_t *w =
        (tokio_polled_word_t *)bpf_map_lookup_elem(&tokio_polled_headers, &word);
    if (!w) {
        return NULL;
    }
    return &w->lanes[slot & (k_tokio_polled_lanes - 1)];
}

static __always_inline void tokio_mark_polled(u32 tgid, u64 header) {
    u8 *lane = tokio_polled_lane(tgid, header);
    if (lane) {
        *lane = 1;
    }
}

static __always_inline void tokio_clear_polled(u32 tgid, u64 header) {
    u8 *lane = tokio_polled_lane(tgid, header);
    if (lane) {
        *lane = 0;
    }
}

static __always_inline u8 tokio_was_polled(u32 tgid, u64 header) {
    const u8 *lane = tokio_polled_lane(tgid, header);
    return lane ? *lane : 0;
}
