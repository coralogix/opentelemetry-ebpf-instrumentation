// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/tokio_task_slots.h>

// Multiplicative hash of (tgid, Header) into a slot. The tgid folds in because Header
// addresses alias across processes; the multiply spreads the address bits the cell
// alignment leaves at zero.
static __always_inline u32 tokio_slot_index(u32 tgid, u64 header) {
    const u64 mixed = (header ^ ((u64)tgid << 32)) * 0x9E3779B97F4A7C15ULL;
    return (u32)(mixed >> (64 - k_tokio_slot_shift));
}

static __always_inline u8 *tokio_slot_lane(u32 tgid, u64 header) {
    const u32 slot = tokio_slot_index(tgid, header);
    const u32 word = slot / k_tokio_slot_lanes;
    tokio_task_slot_word_t *w =
        (tokio_task_slot_word_t *)bpf_map_lookup_elem(&tokio_task_slots, &word);
    if (!w) {
        return NULL;
    }
    return &w->live[slot & (k_tokio_slot_lanes - 1)];
}

// Returns whether a count was taken: a saturated slot takes none, so the caller must not
// release one later either.
static __always_inline u8 tokio_slot_inc(u32 tgid, u64 header) {
    u8 *lane = tokio_slot_lane(tgid, header);
    if (!lane || *lane >= k_tokio_slot_max) {
        return 0;
    }
    (*lane)++;
    return 1;
}

static __always_inline void tokio_slot_dec(u32 tgid, u64 header) {
    u8 *lane = tokio_slot_lane(tgid, header);
    if (lane && *lane) {
        (*lane)--;
    }
}

static __always_inline u8 tokio_slot_live(u32 tgid, u64 header) {
    const u8 *lane = tokio_slot_lane(tgid, header);
    return lane && *lane;
}
