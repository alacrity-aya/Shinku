#pragma once

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <common/constants.h>
#include <common/types.h>

// Parse up to the DNS header
// Returns: Pointer to the DNS Header, or NULL on failure
// Output parameter: Updates 'cursor' to point past the DNS Header (start of the Question section)
static __always_inline struct dns_hdr*
parse_dns_header(struct xdp_md* ctx, void** cursor, void* data_end) {
    void* data = (void*)(long)ctx->data;

    // 1. Ethernet Header
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return NULL;

    __u16 proto = eth->h_proto;
    void* next_hdr = (void*)(eth + 1);

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr* vlan = next_hdr;
            if ((void*)(vlan + 1) > data_end)
                return NULL;

            proto = vlan->h_vlan_encapsulated_proto;
            next_hdr = (void*)(vlan + 1);
        } else {
            break;
        }
    }

    // After VLAN stripping, we must be looking at IPv4
    if (proto != bpf_htons(ETH_P_IP))
        return NULL;

    // 2. IP Header
    struct iphdr* ip = next_hdr;
    if ((void*)(ip + 1) > data_end)
        return NULL;

    if (ip->protocol != IPPROTO_UDP)
        return NULL;

    __u32 ip_len = ip->ihl * 4;
    // Safety check for IHL and packet boundaries
    if (ip_len < sizeof(struct iphdr) || (void*)ip + ip_len > data_end)
        return NULL;

    // 3. UDP Header
    struct udphdr* udp = (void*)ip + ip_len;
    if ((void*)(udp + 1) > data_end)
        return NULL;

    if (udp->dest != bpf_htons(DNS_PORT))
        return NULL;

    // 4. DNS Header
    struct dns_hdr* dns = (void*)(udp + 1);
    if ((void*)(dns + 1) > data_end)
        return NULL;

    // Set cursor to the beginning of the Question Section (QNAME)
    *cursor = (void*)(dns + 1);
    return dns;
}
