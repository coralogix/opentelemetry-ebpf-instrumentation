// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <logger/bpf_dbg.h>
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>
#include <generictracer/protocol_common.h>

// Aerospike native client protocol (proto version 2).
//
// Wire layout (all multi-byte integers big-endian):
//   proto header (8 bytes): version(1)=2, type(1), size(6)  // size = body length
//   as_msg header (22 bytes): header_sz(1)=22, info1(1), info2(1), info3(1),
//       info4(1), result_code(1), ...
//
// The Aerospike client reads a response in two recvs: an 8-byte proto header,
// then a separate read of the body. The generic TCP path keeps only the first
// recv (the 8-byte header) so the result_code (as_msg body byte 5, absolute
// offset 13) is never observed. We accumulate the response recv segments into
// req->rbuf until at least the first full frame is captured, then let the event
// be emitted with a fuller rbuf/resp_len.

enum {
    k_as_proto_hdr_size = 8,
    k_as_msg_hdr_size = 22,
    k_as_proto_version = 2,
    k_as_type_message = 3, // AS_MSG: the data protocol

    // info1 flags (read side)
    k_as_info1_read = 0x01,
    k_as_info1_batch = 0x08,
    // info2 flags (write side)
    k_as_info2_write = 0x01,

    // largest declared proto body we will treat as plausibly Aerospike (128MiB)
    k_as_max_body_len = 128 * 1024 * 1024,
};

// Decode the 6-byte big-endian size field of a proto header (bytes 2..7).
static __always_inline u64 as_proto_body_len(const unsigned char *h) {
    u64 len = 0;
    for (u8 i = 0; i < 6; i++) {
        len = (len << 8) | (u64)h[k_as_proto_hdr_size - 6 + i];
    }
    return len;
}

// Detect a type-3 AS_MSG request frame and classify the connection. Mirrors the
// Go-side parseAerospikeRequest classifier: version==2, type==3, header_sz==22,
// and at least one request-intent bit set.
static __always_inline u8 is_aerospike(connection_info_t *conn_info,
                                       const unsigned char *data,
                                       u32 data_len,
                                       enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_aerospike &&
        *protocol_type != k_protocol_type_unknown) {
        // Already classified, not aerospike.
        return 0;
    }

    if (data_len < k_as_proto_hdr_size + k_as_msg_hdr_size) {
        return 0;
    }

    unsigned char hdr[k_as_proto_hdr_size + k_as_msg_hdr_size] = {};
    bpf_probe_read(hdr, sizeof(hdr), (const void *)data);

    if (hdr[0] != k_as_proto_version || hdr[1] != k_as_type_message) {
        return 0;
    }

    const u64 body_len = as_proto_body_len(hdr);
    if (body_len < k_as_msg_hdr_size || body_len > k_as_max_body_len) {
        return 0;
    }

    // as_msg header begins at offset 8.
    const u8 as_hdr_sz = hdr[k_as_proto_hdr_size + 0];
    const u8 info1 = hdr[k_as_proto_hdr_size + 1];
    const u8 info2 = hdr[k_as_proto_hdr_size + 2];

    if (as_hdr_sz != k_as_msg_hdr_size) {
        return 0;
    }

    const bool is_request =
        (info1 & (k_as_info1_read | k_as_info1_batch)) != 0 || (info2 & k_as_info2_write) != 0;
    if (!is_request) {
        return 0;
    }

    *protocol_type = k_protocol_type_aerospike;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    bpf_dbg_printk("is_aerospike: aerospike! body_len=%d", (u32)body_len);
    return 1;
}

// Accumulates response recv segments into req->rbuf so the full first frame
// (proto header + as_msg body, through at least the result_code at offset 13)
// is captured before the event is emitted.
//
// Returns -1 to wait for more data, 0 when the first frame is complete.
//
// Unlike the single-recv protocols, the Aerospike response arrives as separate
// recvs (8-byte header, then body). We write each segment into req->rbuf at the
// running offset (req->resp_len), so by completion rbuf holds [header|body].
// The finalize path in protocol_tcp.h must NOT overwrite rbuf with the last
// recv for aerospike (it uses the accumulated rbuf instead).
static __always_inline int
aerospike_response_accumulate(tcp_req_t *req, const void *u_buf, u32 bytes_len) {
    if (bytes_len == 0) {
        return -1;
    }

    // Append this segment into rbuf at the current offset. We only need the
    // first frame (proto header + as_msg header through result_code = 30 bytes),
    // so we restrict accumulation to the lower half of rbuf. Keeping both the
    // offset and the copy length bounded by k_tcp_res_len/2 lets the verifier
    // prove off + to_copy <= k_tcp_res_len (the rbuf size).
    if (req->resp_len < (k_tcp_res_len / 2)) {
        u32 off = req->resp_len;
        bpf_clamp_umax(off, (k_tcp_res_len / 2));
        u32 to_copy = bytes_len;
        bpf_clamp_umax(to_copy, (k_tcp_res_len / 2));
        bpf_probe_read(req->rbuf + off, to_copy, u_buf);
    }

    req->resp_len += bytes_len;

    // Need at least the proto header to know the declared body length.
    if (req->resp_len < k_as_proto_hdr_size) {
        bpf_dbg_printk("aerospike response: waiting for header, acc=%d", req->resp_len);
        return -1;
    }

    const u64 body_len = as_proto_body_len(req->rbuf);
    // First full frame length, capped at what rbuf can hold.
    u64 frame_len = body_len + k_as_proto_hdr_size;
    if (frame_len > k_tcp_res_len) {
        frame_len = k_tcp_res_len;
    }

    if (req->resp_len < frame_len) {
        bpf_dbg_printk(
            "aerospike response: partial, acc=%d frame=%d", req->resp_len, (u32)frame_len);
        return -1;
    }

    bpf_dbg_printk("aerospike response: complete, acc=%d", req->resp_len);
    return 0;
}
