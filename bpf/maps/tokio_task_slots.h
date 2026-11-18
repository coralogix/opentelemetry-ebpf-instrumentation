// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// One-byte count of the live known tasks per slot, hashed from (tgid, Header). An array,
// so it survives the eviction of the task maps: at the LocalSet schedule hook it tells the
// wake of an evicted task from a new spawn (devdoc "Evicted tasks are not adopted at their
// wake"). Bytes, so a change needs no atomics, which the 5.8 floor lacks.
enum {
    k_tokio_slot_lanes = 8,
    k_tokio_slot_shift = 21,
    k_tokio_slot_words = (1U << k_tokio_slot_shift) / k_tokio_slot_lanes,
    k_tokio_slot_max = 255,
};

typedef struct tokio_task_slot_word {
    u8 live[k_tokio_slot_lanes];
} tokio_task_slot_word_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32); // slot / k_tokio_slot_lanes
    __type(value, tokio_task_slot_word_t);
    __uint(max_entries, k_tokio_slot_words);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_task_slots SEC(".maps");
