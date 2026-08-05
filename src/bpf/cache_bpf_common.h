// SPDX-License-Identifier: GPL-2.0-only
/* Shared dependencies, constants, and structs for the cache BPF parts. */
#pragma once

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf/arena/bpf_arena_common.h"
#include "bpf_log.h"
#include "ebpf_cache_abi.h"
#include "ebpf_cache_fingerprint.h"

#define SHINKU_DNS_PORT 53U
#define SHINKU_ETH_P_IP 0x0800U
#define SHINKU_ETH_ADDRESS_BYTES 6U
#define SHINKU_TC_ACT_OK 0
#define SHINKU_DNS_HEADER_BYTES 12U
#define SHINKU_ETH_IPV4_UDP_BYTES 42U
#define SHINKU_MAX_FRAME_BYTES (SHINKU_ETH_IPV4_UDP_BYTES + SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES)
#define SHINKU_PACKET_RING_BYTES (16U * 1024U * 1024U)

#define DNS_QR 0x8000U
#define DNS_OPCODE 0x7800U
#define DNS_TC 0x0200U
#define DNS_RD 0x0100U
#define DNS_Z 0x0040U
#define DNS_AD 0x0020U
#define DNS_CD 0x0010U
#define DNS_RCODE 0x000fU

struct dns_header {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

struct packet_scratch {
    struct ebpf_cache_slot_header header;
    __u16 ttl_offsets[SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS];
    __u8 canonical_question[264];
    __u8 frame[SHINKU_MAX_FRAME_BYTES];
};

struct question_facts {
    __u16 qname_size;
    __u16 question_size;
    __be16 question_type;
    __be16 question_class;
};

struct packet_view {
    struct ethhdr* eth;
    struct iphdr* ip;
    struct udphdr* udp;
    struct dns_header* dns;
    __u16 dns_size;
};

static __always_inline void reader_barrier(void) {
    asm volatile("" ::: "memory");
}
