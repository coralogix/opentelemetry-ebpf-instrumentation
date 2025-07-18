#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/http_buf_size.h>
#include <common/http_info.h>
#include <common/map_sizing.h>
#include <common/msg_buffer.h>
#include <common/protocol_defs.h>
#include <common/tp_info.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

#define MIN_HTTP_SIZE 12      // HTTP/1.1 CCC is the smallest valid request we can have
#define MIN_HTTP_REQ_SIZE 9   // OPTIONS / is the largest
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--
#define MAX_HTTP_STATUS 599

// should be enough for most URLs, we may need to extend it if not.
#define TRACE_BUF_SIZE 1024 // must be power of 2, we do an & to limit the buffer size

// 100K and above we try to track the response actual time with kretprobes
#define KPROBES_LARGE_RESPONSE_LEN 100000

// Max of HTTP, HTTP2/GRPC and TCP buffers. Used in sk_msg
#define MAX_PROTOCOL_BUF_SIZE 256

#define CONN_INFO_FLAG_TRACE 0x1

#define FLAGS_SIZE_BYTES 1
#define TRACE_ID_CHAR_LEN 32
#define SPAN_ID_CHAR_LEN 16
#define FLAGS_CHAR_LEN 2
#define TP_MAX_VAL_LENGTH 55
#define TP_MAX_KEY_LENGTH 11

// Preface PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n https://datatracker.ietf.org/doc/html/rfc7540#section-3.5
#define MIN_HTTP2_SIZE 24

enum protocol_type : u8 {
    // Default value, used when the protocol is not known or will be determined/classified
    // in userspace.
    k_protocol_type_unknown = 0,
    k_protocol_type_mysql = 1,
};

typedef struct call_protocol_args {
    pid_connection_info_t pid_conn;
    enum protocol_type protocol_type;
    u8 ssl;
    u8 direction;
    u8 packet_type;
    unsigned char small_buf[MIN_HTTP2_SIZE];
    u8 pad[4];
    int bytes_len;
    u16 orig_dport;
    u16 _pad2;
    u64 u_buf;
} call_protocol_args_t;

// Here we keep information on the packets passing through the socket filter
typedef struct protocol_info {
    u32 hdr_len;
    u32 seq;
    u32 ack;
    u16 h_proto;
    u16 tot_len;
    u8 opts_off;
    u8 flags;
    u8 ip_len;
    u8 l4_proto;
} protocol_info_t;

// Here we keep information on the ongoing filtered connections, PID/TID and connection type
typedef struct http_connection_metadata {
    pid_info pid;
    u8 type;
    u8 _pad[3];
} http_connection_metadata_t;

typedef struct http2_conn_stream {
    pid_connection_info_t pid_conn;
    u32 stream_id;
} http2_conn_stream_t;

typedef struct http2_grpc_request {
    u8 flags; // Must be first
    u8 ssl;
    u8 type;
    u8 _pad0[1];
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char data[k_kprobes_http2_buf_size];
    unsigned char ret_data[k_kprobes_http2_ret_buf_size];
    int len;
    // we need this to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    u64 new_conn_id;
    tp_info_t tp;
} http2_grpc_request_t;

// Force emitting struct http_request_trace into the ELF for automatic creation of Golang struct
const http_info_t *unused __attribute__((unused));
const http2_grpc_request_t *unused_http2 __attribute__((unused));

static __always_inline u8 is_http_request_buf(const unsigned char *p) {
    //HTTP/1.x
    return (((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') &&
             (p[4] == '/')) || // GET
            ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') &&
             (p[5] == '/')) || // POST
            ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') &&
             (p[4] == '/')) || // PUT
            ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') &&
             (p[5] == ' ') && (p[6] == '/')) || // PATCH
            ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') &&
             (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) || // DELETE
            ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') &&
             (p[5] == '/')) || // HEAD
            ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') &&
             (p[5] == 'N') && (p[6] == 'S') && (p[7] == ' ') && (p[8] == '/')) // OPTIONS
    );
}
