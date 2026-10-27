// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Polled-Header marks: the slot hash stays inside the map, a mark round-trips through
// mark, test and clear, and both the process and the address take part in the slot.

#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tokio_polled.h>

// The kernel preallocates an array map: every word exists.
static tokio_polled_word_t words[k_tokio_polled_words];

static void *lookup(void *map, const void *key) {
    if (map != (void *)&tokio_polled_headers) {
        return NULL;
    }
    const u32 word = *(const u32 *)key;
    if (word >= k_tokio_polled_words) {
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

static void test_slot_stays_inside_the_map(void) {
    const u64 headers[] = {0, 0x80, k_header, 0x7fffffffff80ULL, ~0ULL};
    const u32 tgids[] = {0, 1, k_tgid, ~0u};
    for (unsigned h = 0; h < sizeof(headers) / sizeof(headers[0]); h++) {
        for (unsigned t = 0; t < sizeof(tgids) / sizeof(tgids[0]); t++) {
            const u32 slot = tokio_polled_slot(tgids[t], headers[h]);
            check(slot < (1u << k_tokio_polled_slots_shift), "slot is below the slot count");
            check(slot / k_tokio_polled_lanes < k_tokio_polled_words, "word is below the map size");
        }
    }
}

static void test_mark_round_trip(void) {
    memset(words, 0, sizeof(words));
    check(!tokio_was_polled(k_tgid, k_header), "an unmarked header reads as not polled");
    tokio_mark_polled(k_tgid, k_header);
    check(tokio_was_polled(k_tgid, k_header), "a marked header reads as polled");
    tokio_mark_polled(k_tgid, k_header);
    check(tokio_was_polled(k_tgid, k_header), "marking twice keeps the mark");
    tokio_clear_polled(k_tgid, k_header);
    check(!tokio_was_polled(k_tgid, k_header), "a cleared header reads as not polled");
}

static void test_mark_is_per_process_and_per_cell(void) {
    memset(words, 0, sizeof(words));
    tokio_mark_polled(k_tgid, k_header);
    check(!tokio_was_polled(k_other_tgid, k_header), "another process has its own slot");
    check(!tokio_was_polled(k_tgid, k_header + k_cell_size), "the next cell has its own slot");
    tokio_clear_polled(k_other_tgid, k_header);
    tokio_clear_polled(k_tgid, k_header + k_cell_size);
    check(tokio_was_polled(k_tgid, k_header), "clearing a neighbour keeps the mark");
}

static void test_missing_word_reads_as_not_polled(void) {
    bpf_map_lookup_elem_hook = NULL;
    tokio_mark_polled(k_tgid, k_header);
    check(!tokio_was_polled(k_tgid, k_header), "a missing word reads as not polled");
    bpf_map_lookup_elem_hook = lookup;
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup;
    test_slot_stays_inside_the_map();
    test_mark_round_trip();
    test_mark_is_per_process_and_per_cell();
    test_missing_word_reads_as_not_polled();
    if (failures) {
        return 1;
    }
    printf("bpf_tokio_polled_headers: all tests passed\n");
    return 0;
}
