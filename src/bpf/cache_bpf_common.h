// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file cache_bpf_common.h
 * @brief Shared dependencies, constants, and structs for the cache BPF parts.
 *
 * Pulled in by every cache_bpf_*.h header; defines the wire constants used to
 * validate the packet envelope, the on-stack scratch layout, and the views
 * passed between the parse, fingerprint, snapshot, and pending helpers.
 */
#pragma once

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf/arena/bpf_arena_common.h"
#include "bpf_log.h"
#include "ebpf_cache_abi.h"
#include "ebpf_cache_fingerprint.h"

#define SHINKU_DNS_PORT 53U                           ///< IANA UDP port for DNS.
#define SHINKU_ETH_P_IP 0x0800U                       ///< EtherType for IPv4.
#define SHINKU_ETH_ADDRESS_BYTES 6U                    ///< Length of an Ethernet MAC address in bytes.
#define SHINKU_TC_ACT_OK 0                             ///< TC action code: continue to the next filter.
#define SHINKU_DNS_HEADER_BYTES 12U                    ///< Size of the fixed DNS message header in bytes.
#define SHINKU_ETH_IPV4_UDP_BYTES 42U                  ///< Bytes of Ethernet + IPv4 + UDP headers combined.
#define SHINKU_MAX_FRAME_BYTES (SHINKU_ETH_IPV4_UDP_BYTES + SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES) ///< Largest frame the hit path assembles.
#define SHINKU_PACKET_RING_BYTES (16U * 1024U * 1024U) ///< Size of the packet-event ring buffer in bytes.

#define DNS_QR 0x8000U     ///< DNS flags mask: query/response (1 = response).
#define DNS_OPCODE 0x7800U ///< DNS flags mask: opcode bits.
#define DNS_TC 0x0200U      ///< DNS flags mask: truncation.
#define DNS_RD 0x0100U      ///< DNS flags mask: recursion desired.
#define DNS_Z 0x0040U       ///< DNS flags mask: reserved (must be zero).
#define DNS_AD 0x0020U      ///< DNS flags mask: authenticated data.
#define DNS_CD 0x0010U      ///< DNS flags mask: checking disabled.
#define DNS_RCODE 0x000fU   ///< DNS flags mask: reply code.

/// Packed DNS message header (12 bytes), in network byte order on the wire.
struct dns_header {
    __be16 id;      ///< Transaction id.
    __be16 flags;   ///< Flags word (see @ref DNS_QR and friends).
    __be16 qdcount; ///< Number of entries in the question section.
    __be16 ancount; ///< Number of entries in the answer section.
    __be16 nscount; ///< Number of entries in the authority section.
    __be16 arcount; ///< Number of entries in the additional section.
} __attribute__((packed));

/// Per-CPU scratch buffer used by the hit path to assemble a response frame.
struct packet_scratch {
    struct ebpf_cache_slot_header header;                  ///< Snapshot of the slot header under test.
    __u16 ttl_offsets[SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS];  ///< TTL byte offsets copied from the slot.
    __u8 canonical_question[264];                          ///< Canonical question name + type/class.
    __u8 frame[SHINKU_MAX_FRAME_BYTES];                   ///< Assembled Ethernet/IPv4/UDP/DNS frame.
};

/// Facts about a parsed DNS question, used to drive fingerprinting and eligibility.
struct question_facts {
    __u16 qname_size;        ///< Wire size of the canonical question name in bytes.
    __u16 question_size;     ///< Total wire size of the question (name + type + class).
    __be16 question_type;    ///< DNS QTYPE (network order).
    __be16 question_class;   ///< DNS QCLASS (network order).
};

/// Borrowed view over the parsed envelope of a received packet.
struct packet_view {
    struct ethhdr* eth;     ///< Ethernet header.
    struct iphdr* ip;       ///< IPv4 header.
    struct udphdr* udp;     ///< UDP header.
    struct dns_header* dns; ///< DNS header.
    __u16 dns_size;         ///< Number of DNS message bytes (UDP length minus UDP header).
};

/// @brief Compiler barrier to order the seqlock read sequence on the hit path.
static __always_inline void reader_barrier(void) {
    asm volatile("" ::: "memory");
}
