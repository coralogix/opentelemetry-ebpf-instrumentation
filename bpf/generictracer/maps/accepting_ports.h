#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/accepting_port.h>
#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct accepting_port);
    __type(value, bool);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} accepting_ports SEC(".maps");
