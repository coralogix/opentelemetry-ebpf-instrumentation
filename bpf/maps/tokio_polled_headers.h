// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Marks of the task Headers polled since OBI attached and not yet deallocated, one byte per
// slot, hashed from (tgid, Header). An array, not an LRU: it survives the eviction of the
// task maps, which is what lets the LocalSet schedule hook tell the wake of a task whose
// entry was evicted from the spawn of a new one (a parent recorded at that wake would be
// the waker's, not the spawner's). A slot collision reads as "polled" and only withholds a
// parent. Bytes rather than bits: a mark is one store, so two CPUs marking neighbours
// cannot lose each other's write, and the 5.8 floor has no atomic or. Hashed, not keyed by
// pid, so not purged with a process: a stale slot costs a reused pid one parentless task at
// that address, cleared again at its dealloc.
enum {
    k_tokio_polled_lanes = 8,
    k_tokio_polled_slots_shift = 21,
    k_tokio_polled_words = (1u << k_tokio_polled_slots_shift) / k_tokio_polled_lanes,
};

typedef struct tokio_polled_word {
    u8 lanes[k_tokio_polled_lanes];
} tokio_polled_word_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32); // slot / k_tokio_polled_lanes
    __type(value, tokio_polled_word_t);
    __uint(max_entries, k_tokio_polled_words);
    __uint(pinning, OBI_PIN_INTERNAL);
} tokio_polled_headers SEC(".maps");
