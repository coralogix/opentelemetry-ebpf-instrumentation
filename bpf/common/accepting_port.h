#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

struct accepting_port {
    u32 netns;
    u16 port;
    u8 _pad[2];
};

static __always_inline struct accepting_port accepting_port_from_skc(struct sock_common *skc) {
    struct accepting_port ap = {
        .port = BPF_CORE_READ(skc, skc_num),
        .netns = BPF_CORE_READ(skc, skc_net.net, ns.inum),
    };
    return ap;
}

static __always_inline struct accepting_port accepting_port_from_sk(struct sock *sk) {
    struct sock_common *skc = (struct sock_common *)sk;
    return accepting_port_from_skc(skc);
}
