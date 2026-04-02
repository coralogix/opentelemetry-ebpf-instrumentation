// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Socket-local flag indicating this socket carries HTTP/2 traffic.
// Set when the sk_msg program detects an HTTP/2 connection preface.
// Used on subsequent sends to skip the preface check and go straight
// to H2 frame scanning.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u8);
} sk_h2_conn_flag SEC(".maps");
