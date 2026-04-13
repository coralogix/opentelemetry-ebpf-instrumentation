// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/fd_info.h>
#include <common/connection_info.h>
#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

#include <maps/haproxy_upstream.h>

#include <pid/pid.h>

// Per-version struct offsets, populated from user space at uprobe-attach time
// (see pkg/internal/ebpf/generictracer/haproxy_offsets.go). Defaults match
// HAProxy 2.8.x — used as a fallback if version detection fails. Other LTS
// versions (2.6, 3.0, 3.2) override these via the bpf2go Variables map.
volatile const s32 haproxy_stream_scf = 632;     // struct stream:  scf  (frontend stconn *)
volatile const s32 haproxy_stream_scb = 640;     // struct stream:  scb  (backend stconn *)
volatile const s32 haproxy_stconn_sedesc = 40;   // struct stconn:  sedesc (struct sedesc *)
volatile const s32 haproxy_sedesc_conn = 8;      // struct sedesc:  conn (struct connection *)
volatile const s32 haproxy_conn_handle_fd = 104; // struct connection: handle.fd (int)
volatile const s32 haproxy_conn_src = 128;       // struct connection: src (sockaddr_storage *)

// Walk: stream -> scX (stconn *) -> sedesc -> conn (struct connection *).
// Returns NULL if any step dereferences a NULL pointer.
static __always_inline void *haproxy_stream_to_conn(void *stream, s32 stconn_offset) {
    void *stconn = NULL;
    bpf_probe_read(&stconn, sizeof(void *), stream + stconn_offset);
    if (!stconn) {
        return NULL;
    }
    void *sedesc = NULL;
    bpf_probe_read(&sedesc, sizeof(void *), stconn + haproxy_stconn_sedesc);
    if (!sedesc) {
        return NULL;
    }
    void *conn = NULL;
    bpf_probe_read(&conn, sizeof(void *), sedesc + haproxy_sedesc_conn);
    return conn;
}

// ---------------------------------------------------------------------------
// Entry probe on back_handle_st_rdy(struct stream *s).
//
// HAProxy's backend state machine transitions to SC_ST_RDY whenever a stream
// is about to send on a backend connection — both for cold connections (just
// established by tcp_connect_server) and for warm connections pulled from
// srv->per_thr->idle_conns. Hooking here covers both paths uniformly.
//
// We do the *full* walk in the ENTRY probe (not the return probe) because
// the actual send() to the backend FD happens inside back_handle_st_rdy /
// shortly after it returns, and the kernel-side find_haproxy_parent_trace
// lookup must already see our map entry. The connection is in SC_ST_RDY by
// definition when this function is entered, so scb -> sedesc -> conn ->
// handle.fd is fully populated and safe to walk on entry.
//
// Walks both connectors:
//   stream -> scf -> sedesc -> conn -> src       => frontend peer (client)
//   stream -> scb -> sedesc -> conn -> handle.fd => backend socket FD
//
// Stores haproxy_upstream[(pid, backend_fd, FD_CLIENT)] = frontend_peer
// so that, when the kernel side observes outgoing traffic on the backend
// FD, find_haproxy_parent_trace can recover the frontend peer address and
// look up the parent server trace via server_traces_aux.
// ---------------------------------------------------------------------------
SEC("uprobe/haproxy:back_handle_st_rdy")
int obi_haproxy_back_handle_st_rdy(struct pt_regs *ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    void *stream = (void *)PT_REGS_PARM1(ctx);
    bpf_dbg_printk("=(haproxy)= back_handle_st_rdy id=%d stream=%llx", id, stream);
    if (!stream) {
        return 0;
    }

    // Frontend connection -> get peer (client) sockaddr at conn->src.
    void *frontend_conn = haproxy_stream_to_conn(stream, haproxy_stream_scf);
    if (!frontend_conn) {
        return 0;
    }

    void *frontend_src = NULL;
    bpf_probe_read(&frontend_src, sizeof(void *), frontend_conn + haproxy_conn_src);
    if (!frontend_src) {
        return 0;
    }

    connection_info_part_t part = {0};
    const u32 host_pid = pid_from_pid_tgid(id);
    parse_sockaddr_info(host_pid, (struct sockaddr *)frontend_src, &part);
    part.type = FD_SERVER;
    bpf_dbg_printk("haproxy frontend peer port=%d", part.port);

    // Backend connection -> get FD at conn->handle.fd.
    void *backend_conn = haproxy_stream_to_conn(stream, haproxy_stream_scb);
    if (!backend_conn) {
        return 0;
    }

    int fd = 0;
    bpf_probe_read(&fd, sizeof(int), backend_conn + haproxy_conn_handle_fd);
    bpf_dbg_printk("haproxy backend conn=%llx fd=%d", backend_conn, fd);

    if (fd > 0) {
        fd_info_t fdinfo = {};
        fd_info(&fdinfo, fd, FD_CLIENT);
        bpf_map_update_elem(&haproxy_upstream, &fdinfo, &part, BPF_ANY);
    }

    return 0;
}
