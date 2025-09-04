// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tracing.h>

#define TP_ENCODED_LEN 8

static unsigned char tp_encoded[TP_ENCODED_LEN] = {
    0x4d, 0x83, 0x21, 0x6b, 0x1d, 0x85, 0xa9, 0x3f}; // hpack encoded "traceparent"
