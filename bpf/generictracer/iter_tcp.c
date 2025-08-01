#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/accepting_port.h>

#include <generictracer/maps/accepting_ports.h>

SEC("iter/tcp")
int obi_iter_tcp(struct bpf_iter__tcp *ctx) {
    struct seq_file *seq = ctx->meta->seq;
    struct sock_common *skc = ctx->sk_common;
    if (!skc) {
        return 0;
    }

    unsigned char skc_state = BPF_CORE_READ(skc, skc_state);
    if (skc_state != TCP_LISTEN) {
        return 0;
    }

    struct accepting_port ap = accepting_port_from_skc(skc);
    bpf_map_update_elem(&accepting_ports, &ap, &(bool){true}, BPF_ANY);

    BPF_SEQ_PRINTF(seq, "Adding accepting port:%d, netns:%d\n", ap.port, ap.netns);

    return 0;
}
