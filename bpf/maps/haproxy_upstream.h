// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/fd_info.h>
#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/map_sizing.h>

// Maps a HAProxy backend connection FD to the frontend (incoming) peer
// address that was associated with it at backend-dispatch time.
// Same shape as nginx_upstream — looked up by the generic correlation
// path in bpf/common/trace_parent.h:find_haproxy_parent_trace.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, fd_info_t);                // (pid, fd, type) of the backend socket
    __type(value, connection_info_part_t); // frontend peer address (the inbound client)
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} haproxy_upstream SEC(".maps");
