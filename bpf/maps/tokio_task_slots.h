// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Live known tasks per slot, one byte per slot, hashed from (tgid, Header). An array, not an
// LRU: it survives the eviction of the task maps, which is what lets the LocalSet schedule
// hook tell the wake of a task whose entry was evicted (its slot is live) from the spawn of
// a new one (its slot is empty); a parent recorded at that wake would be the waker's, not
// the spawner's. A count, not a bit, so the dealloc of a task sharing a slot with a live one
// cannot erase the live one's trace. Taken by every registration that finds no counted
// entry, at a spawn hook or at the first poll of a task with no entry, and released at
// raw::dealloc only by a task whose entry says it took one (tokio_task_state_t.counted): a
// task counted again after an eviction leaks its first count, which only withholds parents
// at its slot, while a decrement for a task that never took one could erase a neighbour's.
// A spawn sharing its slot with a live task loses its parent and nothing else, since it
// still takes its own count; a saturated slot takes no count and releases none. Bytes
// rather than words, so a change is one read-modify-write without
// atomics, which the 5.8 floor lacks; two tasks of one slot changing at the same instant can
// lose a count. Hashed, not keyed by pid, so not purged with a process: the unobserved
// deallocs of a dead process leave a reused pid's tasks at those slots parentless until
// their own dealloc.
enum {
    k_tokio_slot_lanes = 8,
    k_tokio_slot_shift = 21,
    k_tokio_slot_words = (1u << k_tokio_slot_shift) / k_tokio_slot_lanes,
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
