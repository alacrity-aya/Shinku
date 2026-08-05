// SPDX-License-Identifier: GPL-2.0-only
/* Packet envelope and DNS question parsing for the cache BPF program. */
#pragma once

// NOLINTBEGIN(readability-implicit-bool-conversion)

#include "bpf/cache_bpf_common.h"

static __always_inline bool ethernet_unicast(const __u8* address) {
    if ((address[0] & 1U) != 0)
        return false;
    __u8 any = 0;
#pragma clang loop unroll(full)
    for (int index = 0; index < (int)SHINKU_ETH_ADDRESS_BYTES; ++index)
        any |= address[index];
    return any != 0;
}

static __always_inline bool ipv4_unicast(__be32 address) {
    const __u32 host = bpf_ntohl(address);
    return host != 0 && (host < 0xe0000000U || host > 0xefffffffU) && host != 0xffffffffU;
}

static __always_inline bool parse_envelope(void* data, void* data_end, bool query, struct packet_view* view) {
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end || eth->h_proto != bpf_htons(SHINKU_ETH_P_IP))
        return false;
    if (!ethernet_unicast(eth->h_dest) || !ethernet_unicast(eth->h_source))
        return false;

    struct iphdr* ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
        return false;
    if ((bpf_ntohs(ip->frag_off) & 0x3fffU) != 0)
        return false;
    if (query && (!ipv4_unicast(ip->saddr) || !ipv4_unicast(ip->daddr)))
        return false;

    struct udphdr* udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end)
        return false;
    if (query ? udp->dest != bpf_htons(SHINKU_DNS_PORT) : udp->source != bpf_htons(SHINKU_DNS_PORT))
        return false;
    if (query ? udp->source == 0 : udp->dest == 0)
        return false;

    const __u16 ip_size = bpf_ntohs(ip->tot_len);
    if (ip_size < sizeof(*ip) + sizeof(struct udphdr) + SHINKU_DNS_HEADER_BYTES)
        return false;
    if ((__u8*)ip + ip_size > (__u8*)data_end)
        return false;

    const __u16 udp_size = bpf_ntohs(udp->len);
    if (udp_size < sizeof(*udp) + SHINKU_DNS_HEADER_BYTES || ip_size != sizeof(*ip) + udp_size)
        return false;

    struct dns_header* dns = (void*)(udp + 1);
    __u8* dns_end = (__u8*)udp + udp_size;
    if ((void*)(dns + 1) > data_end || dns_end > (__u8*)data_end)
        return false;

    view->eth = eth;
    view->ip = ip;
    view->udp = udp;
    view->dns = dns;
    view->dns_size = udp_size - sizeof(*udp);
    return true;
}

static __always_inline bool parse_question(
    struct dns_header* dns,
    void* packet_end,
    __u16 dns_size,
    struct packet_scratch* scratch,
    struct question_facts* facts
) {
    if (dns_size < SHINKU_DNS_HEADER_BYTES)
        return false;
    __u8* cursor = (__u8*)(dns + 1);
    __u8* data_end = packet_end;
    barrier_var(data_end);
    const __u32 question_capacity = dns_size - SHINKU_DNS_HEADER_BYTES;
    __u32 position = 0;
    bool complete = false;

#pragma clang loop unroll(disable)
    for (__u32 index = 0; index < 255; ++index) {
        if (position >= question_capacity || cursor + position + 1 > data_end)
            return false;
        const __u8 byte = cursor[position];
        if ((byte & 0xc0U) != 0)
            return false;
        scratch->canonical_question[position] = byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
        ++position;
        if (byte == 0) {
            complete = true;
            break;
        }
        if (byte > 63 || position + byte > 255 || position + byte > question_capacity)
            return false;
#pragma clang loop unroll(disable)
        for (__u32 label_index = 0; label_index < 63; ++label_index) {
            if (label_index >= byte)
                break;
            if (cursor + position + label_index + 1 > data_end)
                return false;
            const __u8 label_byte = cursor[position + label_index];
            scratch->canonical_question[position + label_index] =
                label_byte >= 'A' && label_byte <= 'Z' ? label_byte + ('a' - 'A') : label_byte;
        }
        position += byte;
    }
    if (!complete || position > 255 || position > question_capacity || question_capacity - position < 4
        || cursor + position + 4 > data_end)
        return false;

    facts->qname_size = position;
    facts->question_size = position + 4;
    __builtin_memcpy(&facts->question_type, cursor + position, sizeof(facts->question_type));
    __builtin_memcpy(&facts->question_class, cursor + position + 2, sizeof(facts->question_class));
    return true;
}

static __always_inline bool eligible_query(const struct packet_view* view, const struct question_facts* question) {
    const __u16 flags = bpf_ntohs(view->dns->flags);
    if ((flags & (DNS_QR | DNS_OPCODE | DNS_TC | DNS_Z | DNS_AD | DNS_CD)) != 0 || (flags & DNS_RD) == 0)
        return false;
    return view->dns->qdcount == bpf_htons(1) && view->dns->ancount == 0 && view->dns->nscount == 0
        && view->dns->arcount == 0 && question->question_type == bpf_htons(1)
        && question->question_class == bpf_htons(1)
        && view->dns_size == SHINKU_DNS_HEADER_BYTES + question->question_size;
}

static __always_inline bool response_question(const struct packet_view* view, const struct question_facts* question) {
    const __u16 flags = bpf_ntohs(view->dns->flags);
    const __u16 rcode = flags & DNS_RCODE;
    return (flags & DNS_QR) != 0 && (flags & (DNS_OPCODE | DNS_TC | DNS_Z | DNS_CD)) == 0 && (flags & DNS_RD) != 0
        && (rcode == 0 || rcode == 3) && view->dns->qdcount == bpf_htons(1) && view->dns->arcount == 0
        && question->question_type == bpf_htons(1) && question->question_class == bpf_htons(1);
}

// NOLINTEND(readability-implicit-bool-conversion)
