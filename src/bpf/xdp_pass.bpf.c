// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file xdp_pass.bpf.c
 * @brief Minimal XDP pass-through program for veth peer interfaces.
 *
 * Required on veth peer interfaces to receive XDP_TX frames. Without this
 * program, XDP_TX sent from the other side of the veth pair is silently dropped.
 */
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

/**
 * @brief Pass every packet through unchanged.
 *
 * Attached to the veth peer so the cache program's XDP_TX responses are
 * received rather than silently dropped by an absent program.
 */
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
