// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Live-task slot counts: the slot hash stays inside the map, a count round-trips through
// increment, test and decrement, a neighbour's decrement does not erase a live task, the
// count saturates, and both the process and the address take part in the slot.

#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tokio_slots.h>

// The kernel preallocates an array map: every word exists.
static tokio_task_slot_word_t words[k_tokio_slot_words];

static void *lookup(void *map, const void *key) {
    if (map != (void *)&tokio_task_slots) {
        return NULL;
    }
    const u32 word = *(const u32 *)key;
    if (word >= k_tokio_slot_words) {
        return NULL;
    }
    return &words[word];
}

static int failures;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static const u32 k_tgid = 4242;
static const u32 k_other_tgid = 4243;
// Cells are 128-byte aligned; the next cell is 128 bytes up.
static const u64 k_header = 0x7f1234567f80ULL;
static const u64 k_cell_size = 128;

static u8 count_of(u32 tgid, u64 header) {
    const u8 *lane = tokio_slot_lane(tgid, header);
    return lane ? *lane : 0;
}

static void test_slot_stays_inside_the_map(void) {
    const u64 headers[] = {0, 0x80, k_header, 0x7fffffffff80ULL, ~0ULL};
    const u32 tgids[] = {0, 1, k_tgid, ~0u};
    for (unsigned h = 0; h < sizeof(headers) / sizeof(headers[0]); h++) {
        for (unsigned t = 0; t < sizeof(tgids) / sizeof(tgids[0]); t++) {
            const u32 slot = tokio_slot_index(tgids[t], headers[h]);
            check(slot < (1u << k_tokio_slot_shift), "slot is below the slot count");
            check(slot / k_tokio_slot_lanes < k_tokio_slot_words, "word is below the map size");
        }
    }
}

static void test_count_round_trip(void) {
    memset(words, 0, sizeof(words));
    check(!tokio_slot_live(k_tgid, k_header), "an empty slot reads as not live");
    tokio_slot_inc(k_tgid, k_header);
    check(tokio_slot_live(k_tgid, k_header), "a counted slot reads as live");
    tokio_slot_dec(k_tgid, k_header);
    check(!tokio_slot_live(k_tgid, k_header), "the last decrement empties the slot");
    tokio_slot_dec(k_tgid, k_header);
    check(count_of(k_tgid, k_header) == 0, "an empty slot does not wrap on decrement");
}

static void test_shared_slot_keeps_the_live_task(void) {
    memset(words, 0, sizeof(words));
    tokio_slot_inc(k_tgid, k_header);
    tokio_slot_inc(k_tgid, k_header);
    check(count_of(k_tgid, k_header) == 2, "two tasks of one slot count twice");
    tokio_slot_dec(k_tgid, k_header);
    check(tokio_slot_live(k_tgid, k_header), "one task's dealloc keeps the other's slot live");
}

static void test_count_saturates(void) {
    memset(words, 0, sizeof(words));
    for (unsigned i = 0; i < 300; i++) {
        tokio_slot_inc(k_tgid, k_header);
    }
    check(count_of(k_tgid, k_header) == k_tokio_slot_max, "the count stops at its maximum");
    tokio_slot_dec(k_tgid, k_header);
    check(tokio_slot_live(k_tgid, k_header), "a saturated slot stays live after a decrement");
}

static void test_slot_is_per_process_and_per_cell(void) {
    memset(words, 0, sizeof(words));
    tokio_slot_inc(k_tgid, k_header);
    check(!tokio_slot_live(k_other_tgid, k_header), "another process has its own slot");
    check(!tokio_slot_live(k_tgid, k_header + k_cell_size), "the next cell has its own slot");
    tokio_slot_dec(k_other_tgid, k_header);
    tokio_slot_dec(k_tgid, k_header + k_cell_size);
    check(tokio_slot_live(k_tgid, k_header), "a neighbour's decrement keeps the slot live");
}

static void test_missing_word_reads_as_not_live(void) {
    bpf_map_lookup_elem_hook = NULL;
    tokio_slot_inc(k_tgid, k_header);
    check(!tokio_slot_live(k_tgid, k_header), "a missing word reads as not live");
    bpf_map_lookup_elem_hook = lookup;
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup;
    test_slot_stays_inside_the_map();
    test_count_round_trip();
    test_shared_slot_keeps_the_live_task();
    test_count_saturates();
    test_slot_is_per_process_and_per_cell();
    test_missing_word_reads_as_not_live();
    if (failures) {
        return 1;
    }
    printf("bpf_tokio_task_slots: all tests passed\n");
    return 0;
}
