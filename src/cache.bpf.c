#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "bpf_log.h"

#define XDP_DROP 0
#define XDP_ABORTED 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

SEC("xdp")
int xdp_dns_parser(struct xdp_md* ctx) {
    void* data_end = (void*)ctx->data_end;
    void* data = (void*)ctx->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
