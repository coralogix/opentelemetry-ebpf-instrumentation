// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tokio_task.h>

// Host stand-ins for the four maps the birth record reads and writes: one entry per key the
// tests use, looked up by value comparison.
enum { k_entries = 4 };

static u64 thread_keys[k_entries];
static tokio_thread_state_t thread_values[k_entries];
static tokio_task_key_t task_keys[k_entries];
static tokio_task_state_t task_values[k_entries];
static u8 task_present[k_entries];
static tokio_task_key_t id_keys[k_entries];
static tokio_task_id_state_t id_values[k_entries];
static u8 id_present[k_entries];
static pid_key_t birth_keys[k_entries];
static tokio_thread_birth_t birth_values[k_entries];
static u8 birth_present[k_entries];

static void reset(void) {
    memset(thread_keys, 0, sizeof(thread_keys));
    memset(thread_values, 0, sizeof(thread_values));
    memset(task_keys, 0, sizeof(task_keys));
    memset(task_values, 0, sizeof(task_values));
    memset(task_present, 0, sizeof(task_present));
    memset(id_keys, 0, sizeof(id_keys));
    memset(id_values, 0, sizeof(id_values));
    memset(id_present, 0, sizeof(id_present));
    memset(birth_keys, 0, sizeof(birth_keys));
    memset(birth_values, 0, sizeof(birth_values));
    memset(birth_present, 0, sizeof(birth_present));
}

static int task_slot(const tokio_task_key_t *key) {
    for (int i = 0; i < k_entries; i++) {
        if (task_present[i] && memcmp(&task_keys[i], key, sizeof(*key)) == 0) {
            return i;
        }
    }
    return -1;
}

static int id_slot(const tokio_task_key_t *key) {
    for (int i = 0; i < k_entries; i++) {
        if (id_present[i] && memcmp(&id_keys[i], key, sizeof(*key)) == 0) {
            return i;
        }
    }
    return -1;
}

static int birth_slot(const pid_key_t *key) {
    for (int i = 0; i < k_entries; i++) {
        if (birth_present[i] && memcmp(&birth_keys[i], key, sizeof(*key)) == 0) {
            return i;
        }
    }
    return -1;
}

static void *lookup(void *map, const void *key) {
    if (map == (void *)&tokio_thread_state) {
        for (int i = 0; i < k_entries; i++) {
            if (thread_keys[i] && thread_keys[i] == *(const u64 *)key) {
                return &thread_values[i];
            }
        }
        return NULL;
    }
    if (map == (void *)&tokio_task_state) {
        const int i = task_slot(key);
        return i < 0 ? NULL : &task_values[i];
    }
    if (map == (void *)&tokio_task_id_state) {
        const int i = id_slot(key);
        return i < 0 ? NULL : &id_values[i];
    }
    if (map == (void *)&tokio_thread_birth) {
        const int i = birth_slot(key);
        return i < 0 ? NULL : &birth_values[i];
    }
    return NULL;
}

static long update(void *map, const void *key, const void *val, unsigned long long flags) {
    (void)flags;
    if (map != (void *)&tokio_thread_birth) {
        return -1;
    }
    int i = birth_slot(key);
    if (i < 0) {
        for (i = 0; i < k_entries && birth_present[i]; i++) {
        }
        if (i == k_entries) {
            return -1;
        }
        birth_present[i] = 1;
        birth_keys[i] = *(const pid_key_t *)key;
    }
    birth_values[i] = *(const tokio_thread_birth_t *)val;
    return 0;
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
static const u64 k_header = 0x7f1234567f80ULL;
static const u64 k_version = 1700000000ULL;
static const u64 k_epoch = 7;
static const u64 k_id = 91;
static const u64 k_id_epoch = 3;

static u64 pid_tgid_of(u32 tid) {
    return ((u64)k_tgid << 32) | tid;
}

static pid_key_t key_of(u32 tid) {
    return (pid_key_t){.pid = k_tgid, .tid = tid, .ns = 1};
}

static void set_thread(int slot, u32 tid, u64 current_task, u64 current_id) {
    thread_keys[slot] = pid_tgid_of(tid);
    thread_values[slot] = (tokio_thread_state_t){
        .current_task = current_task, .current_id = current_id, .tgid = k_tgid, .polled = 1};
}

static void set_task(int slot, u64 header, u64 version, u64 epoch) {
    task_present[slot] = 1;
    task_keys[slot] = tokio_task_key(k_tgid, header);
    task_values[slot] = (tokio_task_state_t){.version = version, .anchor_epoch = epoch};
}

static void set_id(int slot, u64 id, u64 epoch) {
    id_present[slot] = 1;
    id_keys[slot] = tokio_task_key(k_tgid, id);
    id_values[slot] = (tokio_task_id_state_t){.anchor_epoch = epoch};
}

static void record(u32 parent_tid, u32 child_tid) {
    const pid_key_t parent = key_of(parent_tid);
    const pid_key_t child = key_of(child_tid);
    tokio_record_thread_birth(pid_tgid_of(parent_tid), &parent, &child);
}

static void lookup_birth(u32 tgid, u32 tid, u64 *task, u64 *id) {
    const pid_key_t key = key_of(tid);
    tokio_birth_lookup(tgid, &key, task, id);
}

static void test_clone_under_a_polled_task_records_both_identities(void) {
    reset();
    set_thread(0, 10, k_header, k_id);
    set_task(0, k_header, k_version, k_epoch);
    set_id(0, k_id, k_id_epoch);

    record(10, 11);

    const int slot = birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 11, .ns = 1});
    check(slot >= 0, "the child gets a birth record");
    if (slot < 0) {
        return;
    }
    const tokio_thread_birth_t *birth = &birth_values[slot];
    check(birth->task == k_header && birth->version == k_version && birth->epoch == k_epoch,
          "the record carries the task, its stamp and its epoch");
    check(birth->id == k_id && birth->id_epoch == k_id_epoch,
          "the record carries the id and the id entry's epoch");
    check(birth->tgid == k_tgid, "the record carries the process");

    u64 task = 0;
    u64 id = 0;
    lookup_birth(k_tgid, 11, &task, &id);
    check(task == k_header && id == k_id, "both identities resolve while the entries match");
}

static void test_lookup_fails_closed_once_the_task_moved_on(void) {
    reset();
    set_thread(0, 10, k_header, k_id);
    set_task(0, k_header, k_version, k_epoch);
    set_id(0, k_id, k_id_epoch);
    record(10, 11);
    u64 task = 0;
    u64 id = 0;

    task_values[0].anchor_epoch = k_epoch + 1;
    lookup_birth(k_tgid, 11, &task, &id);
    check(task == 0 && id == k_id, "a re-anchored task no longer resolves, the id still does");

    id_values[0].anchor_epoch = k_id_epoch + 1;
    lookup_birth(k_tgid, 11, &task, &id);
    check(task == 0 && id == 0, "a re-anchored id entry no longer resolves");

    task_values[0].anchor_epoch = k_epoch;
    task_values[0].version = k_version + 1;
    lookup_birth(k_tgid, 11, &task, &id);
    check(task == 0, "a reused Header (new stamp) does not resolve");

    task_values[0].version = k_version;
    task_present[0] = 0;
    lookup_birth(k_tgid, 11, &task, &id);
    check(task == 0, "a released task does not resolve");

    task_present[0] = 1;
    id_values[0].anchor_epoch = k_id_epoch;
    lookup_birth(k_other_tgid, 11, &task, &id);
    check(task == 0 && id == 0, "another process's thread key resolves nothing");
}

static void test_clone_outside_a_task_inherits_the_cloners_birth(void) {
    reset();
    set_thread(0, 10, k_header, 0);
    set_task(0, k_header, k_version, k_epoch);
    record(10, 11);
    set_thread(1, 11, 0, 0);

    record(11, 12);

    const int slot = birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 12, .ns = 1});
    check(slot >= 0, "a thread cloned by a never-polling thread gets its cloner's birth");
    if (slot < 0) {
        return;
    }
    check(birth_values[slot].task == k_header && birth_values[slot].version == k_version,
          "the inherited record is the cloner's");
}

static void test_clone_outside_a_task_without_a_birth_records_nothing(void) {
    reset();
    set_thread(0, 10, 0, 0);

    record(10, 11);
    record(20, 21);

    check(birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 11, .ns = 1}) < 0,
          "a thread polling nothing with no birth of its own records nothing");
    check(birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 21, .ns = 1}) < 0,
          "an unknown thread records nothing");
}

static void test_unregistered_identities_are_left_out(void) {
    reset();
    set_thread(0, 10, k_header, k_id);
    set_id(0, k_id, k_id_epoch);
    record(10, 11);
    int slot = birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 11, .ns = 1});
    check(slot >= 0 && birth_values[slot].task == 0 && birth_values[slot].id == k_id,
          "a task with no state entry is left out, the id is kept");

    reset();
    set_thread(0, 10, k_header, k_id);
    set_task(0, k_header, k_version, k_epoch);
    record(10, 11);
    slot = birth_slot(&(pid_key_t){.pid = k_tgid, .tid = 11, .ns = 1});
    check(slot >= 0 && birth_values[slot].task == k_header && birth_values[slot].id == 0,
          "an id with no state entry is left out, the task is kept");
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup;
    bpf_map_update_elem_hook = update;
    test_clone_under_a_polled_task_records_both_identities();
    test_lookup_fails_closed_once_the_task_moved_on();
    test_clone_outside_a_task_inherits_the_cloners_birth();
    test_clone_outside_a_task_without_a_birth_records_nothing();
    test_unregistered_identities_are_left_out();
    if (failures) {
        return 1;
    }
    printf("bpf_tokio_thread_birth: all tests passed\n");
    return 0;
}
