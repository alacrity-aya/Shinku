/* Minimal XDP pass-through program.
 * Required on veth peer interfaces to receive XDP_TX frames.
 * Without this, XDP_TX on the other side of the veth pair silently drops packets. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
