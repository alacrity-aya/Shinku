// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <constants.h>
#include <types.h>

/**
 * @file xdp_parser.h
 * @brief XDP packet parsing utilities for DNS.
 *
 * This header provides inline functions for parsing Ethernet/IP/UDP/DNS
 * headers in XDP programs. All functions are designed for BPF verifier
 * compliance with bounded loops and explicit bounds checks.
 */

struct shinku_vlan_hdr {
    __be16 h_vlan_TCI; /**< VLAN TCI (tag control info) */
    __be16 h_vlan_encapsulated_proto; /**< Encapsulated protocol */
};

/**
 * @brief Skip VLAN tags and return the encapsulated protocol.
 * @param proto Input/output: initial Ethertype, updated to encapsulated protocol.
 * @param next_hdr Input/output: pointer after Ethernet header, updated after VLAN headers.
 * @param data_end Pointer to end of packet data (for bounds checking).
 *
 * Handles 802.1Q and 802.1ad (Q-in-Q) VLAN tagging. Unrolls up to
 * MAX_VLAN_DEPTH VLAN tags to satisfy BPF verifier.
 *
 * @note Always succeeds; if VLAN headers are truncated, simply stops parsing.
 */
static __always_inline void skip_vlan_tags(__u16* proto, void** next_hdr, void* data_end) {
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
        if (*proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD)) {
            struct shinku_vlan_hdr* vlan = *next_hdr;
            if ((void*)(vlan + 1) > data_end)
                return;

            *proto = vlan->h_vlan_encapsulated_proto;
            *next_hdr = (void*)(vlan + 1);
        } else {
            break;
        }
    }
}

/**
 * @brief Parse packet up to the DNS header.
 * @param ctx XDP context containing packet data.
 * @param cursor Output: pointer to start of DNS question section.
 * @param data_end Pointer to end of packet data (for bounds checking).
 * @return Pointer to DNS header, or NULL if parsing fails.
 *
 * Parsing steps:
 *   1. Ethernet header (extract Ethertype)
 *   2. VLAN tags (skip if present, Q-in-Q supported)
 *   3. IPv4 header (verify UDP protocol)
 *   4. UDP header (verify destination port 53)
 *   5. DNS header (return pointer)
 *
 * @note Only supports IPv4. IPv6 support is not implemented.
 * @note Only processes packets destined to DNS port (53).
 */
static __always_inline struct dns_hdr*
parse_dns_header(struct xdp_md* ctx, void** cursor, void* data_end) {
    void* data = (void*)(long)ctx->data;

    /* 1. Ethernet Header */
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return NULL;

    __u16 proto = eth->h_proto;
    void* next_hdr = (void*)(eth + 1);

    /* Skip VLAN tags (Q-in-Q support) */
    skip_vlan_tags(&proto, &next_hdr, data_end);

    /* After VLAN stripping, we must be looking at IPv4 */
    if (proto != bpf_htons(ETH_P_IP))
        return NULL;

    /* 2. IP Header */
    struct iphdr* ip = next_hdr;
    if ((void*)(ip + 1) > data_end)
        return NULL;

    if (ip->protocol != IPPROTO_UDP)
        return NULL;

    __u32 ip_len = ip->ihl * 4;
    /* Safety check for IHL and packet boundaries */
    if (ip_len < sizeof(struct iphdr) || (void*)ip + ip_len > data_end)
        return NULL;

    /* 3. UDP Header */
    struct udphdr* udp = (void*)ip + ip_len;
    if ((void*)(udp + 1) > data_end)
        return NULL;

    if (udp->dest != bpf_htons(DNS_PORT))
        return NULL;

    /* 4. DNS Header */
    struct dns_hdr* dns = (void*)(udp + 1);
    if ((void*)(dns + 1) > data_end)
        return NULL;

    /* Set cursor to the beginning of the Question Section (QNAME) */
    *cursor = (void*)(dns + 1);
    return dns;
}
