// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>
#include <common/trace_common.h>

#include <generictracer/protocol_common.h>
#include <generictracer/k_tracer_tailcall.h>

#include <generictracer/maps/protocol_cache.h>

#include <maps/active_ssl_connections.h>

// Every kafka api packet is prefixed by an header
// https://kafka.apache.org/protocol#protocol_messages
struct kafka_hdr {
    int32_t message_size;
    int16_t api_key;
    int16_t api_version;
    int32_t correlation_id;
    // client-id is a nullable string, we don't parse it for now
};

struct kafka_response_hdr {
    int32_t message_size;
    int32_t correlation_id;
};

struct kafka_state_data {
    int32_t message_size;
};

struct kafka_request_data {
    int32_t correlation_id;
};

enum {
    // Kafka header sizes
    k_kafka_min_hdr_size = 13, // header + tagged fields
    k_kafka_min_response_hdr_size = 9, // header + tagged fields
    k_kafka_hdr_size_without_message_size = 9,
    k_kafka_hdr_message_size_len = 4,

    k_kafka_response_message_size_len = 4,

    // Api keys
    k_kafka_api_key_min = 0,
    k_kafka_api_key_metadata_request = 3,
    k_kafka_api_key_max = 92,

    // Api versions
    k_kafka_api_version_metadata_request_min = 10,
    k_kafka_api_version_metadata_request_max = 13,

    // Large buffer
    k_kafka_large_buf_max_size = 1 << 14, // 16K
    k_kafka_large_buf_max_size_mask = k_kafka_large_buf_max_size - 1,

    // Sanity checks
    k_kafka_payload_length_max = 1 << 13, // 8K
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct kafka_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct kafka_request_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_ongoing_requests SEC(".maps");

SCRATCH_MEM_SIZED(kafka_large_buffers, k_kafka_large_buf_max_size);

static __always_inline u32 read_kafka_response_header(const unsigned char *data, size_t data_len, struct kafka_response_hdr *hdr) {
    if (data_len < k_kafka_min_response_hdr_size) {
        return 0;
    }

    bpf_probe_read((void *)&hdr->message_size, k_kafka_hdr_message_size_len, (const void *)data);
    hdr->message_size = bpf_ntohl(hdr->message_size);
    if (hdr->message_size < k_kafka_min_response_hdr_size || hdr->message_size > k_kafka_payload_length_max) {
        bpf_dbg_printk("read_kafka_response_header: payload length invalid: %d", hdr->message_size);
        return 0;
    }
    bpf_probe_read(&hdr->correlation_id, sizeof(hdr->correlation_id), (const void *)(data + 4));
    hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
    if (hdr->correlation_id < 0) {
        bpf_dbg_printk("read_kafka_response_header: correlation_id invalid: %d", hdr->correlation_id);
        return 0;
    }

    return 1;
}

static __always_inline int read_kafka_message_size(const unsigned char *data, size_t data_len) {
    if (data_len < k_kafka_hdr_message_size_len) {
        return -1;
    }

    int message_size = 0;
    bpf_probe_read(&message_size, k_kafka_hdr_message_size_len, (const void *)data);
    message_size = bpf_ntohl(message_size);

    if (message_size < k_kafka_min_hdr_size || message_size > k_kafka_payload_length_max) {
        bpf_dbg_printk("read_kafka_message_size: payload length invalid: %d", message_size);
        return -1;
    }

    bpf_dbg_printk("read_kafka_message_size: message_size: %d", message_size);
    return message_size;
}

static __always_inline u32 read_kafka_header(const unsigned char *data, size_t data_len, struct kafka_hdr *hdr) {
    if (data_len < k_kafka_hdr_size_without_message_size) {
        return 0;
    }
    if (data_len - k_kafka_hdr_message_size_len != hdr->message_size) {
        bpf_dbg_printk("GREPME data_len - 4 != message_size: %d - %d != %d",
                       data_len,
                       k_kafka_hdr_message_size_len,
                       hdr->message_size);
        return 0;
    }

    bpf_probe_read(&hdr->api_key, sizeof(hdr->api_key), (const void *)(data));
    hdr->api_key = bpf_ntohs(hdr->api_key);
    if (hdr->api_key != k_kafka_api_key_metadata_request) {
        bpf_dbg_printk("read_kafka_header: uninteresting api key: %d", hdr->api_key);
        return 0;
    }
    // if (hdr->api_key < k_kafka_api_key_min || hdr->api_key > k_kafka_api_key_max) {
    //     bpf_dbg_printk("read_kafka_header: invalid api key: %d", hdr->api_key);
    //     return 0;
    // }

    bpf_dbg_printk("read_kafka_header: api_key: %d", hdr->api_key);

    bpf_probe_read(&hdr->api_version, sizeof(hdr->api_version), (const void *)(data + 2));
    hdr->api_version = bpf_ntohs(hdr->api_version);
    if (hdr->api_version < k_kafka_api_version_metadata_request_min ||
        hdr->api_version > k_kafka_api_version_metadata_request_max) {
        bpf_dbg_printk("read_kafka_header: uninteresting api version: %d", hdr->api_version);
        return 0;
    }

    bpf_dbg_printk("read_kafka_header: api_version: %d", hdr->api_version);

    bpf_probe_read(&hdr->correlation_id, sizeof(hdr->correlation_id), (const void *)(data + 4));
    hdr->correlation_id = bpf_ntohl(hdr->correlation_id);
    if (hdr->correlation_id < 0) {
        bpf_dbg_printk("read_kafka_header: correlation_id invalid: %d", hdr->correlation_id);
        return 0;
    }

    bpf_dbg_printk("read_kafka_header: correlation_id: %d", hdr->correlation_id);
    return 1;
}

static __always_inline u32 read_full_kafka_message(const unsigned char *data, size_t data_len, struct kafka_hdr *hdr) {
    int message_size = read_kafka_message_size(data, data_len);
    if (message_size == -1) {
        return 0;
    }
    hdr->message_size = message_size;

    bpf_dbg_printk("GREPME: message_size: %d data_len: %d", message_size, data_len);

    return read_kafka_header(data + k_kafka_hdr_message_size_len, data_len, hdr);
}

// This function is used to store the kafka header if it comes in split packets
// from double send.
// Given the fact that we need to store this for the duration of the full request
// (split in potentially multiple packets), we will **not** process or preserve
// any actual payloads that are exactly 4 bytes long — they are intentionally
// dropped in favor of state storage.
static __always_inline int kafka_store_state_data(const connection_info_t *conn_info,
                                                  const unsigned char *data,
                                                  size_t data_len) {
    if (data_len != k_kafka_hdr_message_size_len) {
        return 0;
    }

    int message_size = read_kafka_message_size(data, data_len);
    if (message_size == -1) {
        return 0;
    }

    struct kafka_state_data new_state_data = {};
    new_state_data.message_size = message_size;
    bpf_dbg_printk("ksts: GREPME store data with msg_size: %d,conn=%llx", new_state_data.message_size, &conn_info);
    bpf_map_update_elem(&kafka_state, conn_info, &new_state_data, BPF_ANY);

    return -1;
}

static __always_inline int kafka_parse_fixup_header(const connection_info_t *conn_info,
                                                    struct kafka_hdr *hdr,
                                                    const unsigned char *data,
                                                    size_t data_len) {
    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, conn_info);
    if (state_data != NULL) {
        // State data found, use stored message size
        hdr->message_size = state_data->message_size;
        bpf_dbg_printk("kafka_parse_fixup_header: GREPME got size from state: %d", hdr->message_size);
        if (read_kafka_header(data, data_len, hdr) != 0) {
            bpf_map_delete_elem(&kafka_state, conn_info);
            return 1;
        }
    } else {
        // Try to parse and validate the header first.
        if (read_full_kafka_message(data, data_len, hdr) > 0) {
            // Header is valid and we have the full data, we can proceed.
            bpf_dbg_printk("kafka_parse_fixup_header: read full header OK");
            return 1;
        }
    }

    bpf_dbg_printk("kafka_parse_fixup_header: failed to parse kafka header");
    return 0;
}

// This is an alternative version of kafka_parse_fixup_header that fills the buffer
// without reading header fields.
static __always_inline int kafka_read_fixup_buffer(const connection_info_t *conn_info,
                                                   unsigned char *buf,
                                                   u32 *buf_len,
                                                   const unsigned char *data,
                                                   u32 data_len) {
    u8 offset = 0;

    if (!is_pow2(kafka_buffer_size)) {
        bpf_dbg_printk("kafka_read_fixup_buffer: bug: kafka_buffer_size is not a power of 2");
        return -1;
    }
    const u32 buf_len_mask = kafka_buffer_size - 1;

    struct kafka_state_data *state_data = bpf_map_lookup_elem(&kafka_state, conn_info);
    if (state_data != NULL) {
        bpf_probe_read(buf, k_kafka_hdr_size_without_message_size, (const void *)state_data);
        offset += k_kafka_hdr_size_without_message_size;
        bpf_map_delete_elem(&kafka_state, conn_info);
    } else {
        if (data_len < k_kafka_min_hdr_size) {
            bpf_dbg_printk("kafka_read_fixup_buffer: data_len is too short: %d", data_len);
            return -1;
        }
    }

    *buf_len = data_len + offset;
    if (*buf_len >= kafka_buffer_size) {
        *buf_len = kafka_buffer_size;
        bpf_dbg_printk("WARN: kafka_read_fixup_buffer: buffer is full, truncating data");
    }

    bpf_probe_read(buf + offset, *buf_len & buf_len_mask, (const void *)data);

    return *buf_len;
}

// Emit a large buffer event for Kafka protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
static __always_inline int kafka_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t *pid_conn,
                                                   const void *u_buf,
                                                   u32 bytes_len,
                                                   u8 packet_type,
                                                   enum large_buf_action action) {
    if (kafka_store_state_data(&pid_conn->conn, u_buf, bytes_len) < 0) {
        bpf_dbg_printk("kafka_send_large_buffer: 4 bytes packet, storing state data");
        return -1;
    }

    if (packet_type == PACKET_TYPE_RESPONSE) {
        // check if this response matches an ongoing request
        struct kafka_request_data *req_data = bpf_map_lookup_elem(&kafka_ongoing_requests, &pid_conn->conn);
        if (!req_data) {
            bpf_dbg_printk("kafka_send_large_buffer: no ongoing request found for this response");
            return 0;
        }
        struct kafka_response_hdr hdr = {};
        if (read_kafka_response_header(u_buf, bytes_len, &hdr) != 0) {
            bpf_dbg_printk("kafka_send_large_buffer: failed to read kafka response header");
            return 0;
        }
        if (hdr.correlation_id != req_data->correlation_id) {
            bpf_dbg_printk("kafka_send_large_buffer: request correlation_id not equal to response correlation_id, %d != %d",
                           hdr.correlation_id,
                           req_data->correlation_id);
            return 0;
        }
        bpf_map_delete_elem(&kafka_ongoing_requests, &pid_conn->conn);
    }

    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)kafka_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk("kafka_send_large_buffer: failed to reserve space for Kafka large buffer");
        return 0;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->action = action;
    __builtin_memcpy((void *)&large_buf->tp, (void *)&req->tp, sizeof(tp_info_t));

    int written =
        kafka_read_fixup_buffer(&pid_conn->conn, large_buf->buf, &large_buf->len, u_buf, bytes_len);
    if (written < 0) {
        bpf_dbg_printk("kafka_send_large_buffer: failed to read buffer, not sending large buffer");
        return 0;
    }

    u32 total_size = sizeof(tcp_large_buffer_t);
    total_size += written > sizeof(void *) ? written : sizeof(void *);

    req->has_large_buffers = true;
    bpf_ringbuf_output(
        &events, large_buf, total_size & k_kafka_large_buf_max_size_mask, get_flags());
    return 0;
}

static __always_inline u8 is_kafka(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_kafka && *protocol_type != k_protocol_type_unknown) {
        // Already classified, not kafka.
        return 0;
    }

    if (kafka_store_state_data(conn_info, data, (size_t)data_len) < 0) {
        bpf_dbg_printk("is_kafka: 4 bytes packet, storing state data");
        return 0;
    }

    struct kafka_hdr hdr = {};
    int res = kafka_parse_fixup_header(conn_info, &hdr, data, data_len);
    if (res == 0) {
        bpf_dbg_printk("is_kafka: failed to parse kafka header");
        unsigned char tmp[20];
        bpf_probe_read(&tmp, 20, &data);
        bpf_dbg_printk("is_kafka GREPME: %d %d %d %d", tmp[0], tmp[1], tmp[2], tmp[3]);
        bpf_dbg_printk("is_kafka: %d %d %d %d", tmp[4], tmp[5], tmp[6], tmp[7]);
        bpf_dbg_printk("is_kafka: %d %d %d %d", tmp[8], tmp[9], tmp[10], tmp[11]);
        bpf_dbg_printk("is_kafka: %d %d %d %d", tmp[12], tmp[13], tmp[14], tmp[15]);
        bpf_dbg_printk("is_kafka: %d %d %d %d", tmp[16], tmp[17], tmp[18], tmp[19]);
        return 0;
    }
    bpf_dbg_printk("is_kafka: kafka_parse_fixup_header res = %d", res);

    *protocol_type = k_protocol_type_kafka;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    bpf_dbg_printk("is_kafka: kafka! api_key=%d api_version=%d correlation_id=%d", hdr.api_key, hdr.api_version, hdr.correlation_id);
    // insert request correlation_id into ongoing requests map
    struct kafka_request_data req_data = {};
    req_data.correlation_id = hdr.correlation_id;
    bpf_map_update_elem(&kafka_ongoing_requests, conn_info, &req_data, BPF_ANY);
    return 1;
}
