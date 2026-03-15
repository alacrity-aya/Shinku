// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once
#ifndef __VMLINUX_H__
    #include <linux/types.h>
    #include <stdint.h>
#endif
#include "constants.h"

/*
 * DNS Header Memory Layout (12 Bytes Total)
 * * Each row represents 16 bits (2 bytes).
 * * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           ID (16 bits)        |         Flags (16 bits)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      QDCOUNT (16 bits)        |       ANCOUNT (16 bits)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      NSCOUNT (16 bits)        |       ARCOUNT (16 bits)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Flags detail:
 * 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct dns_hdr {
    __be16 id; /* Transaction ID */
    __be16 flags; /* DNS Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE) */
    __be16 qdcount; /* Question Count */
    __be16 ancount; /* Answer Record Count */
    __be16 nscount; /* Authority Record Count */
    __be16 arcount; /* Additional Record Count */
} __attribute__((packed));

// Cache Key
struct cache_key {
    __u32 name_hash; // FNV-1a Hash
    __u16 qtype;
    __u16 qclass;
    __u32 _pad;
};

// Cache Entry - stored in __arena cache_entries[] (shared BPF/userspace memory)
//
// Layout (520 bytes):
//   seq (4B) + gen (4B) + pkt (512B)
//   pkt[] starts at offset 8, naturally aligned for 8-byte XDP copies.
//
// Synchronization protocol (seqlock + generation):
//   Writer (userspace): seq++ (odd=writing), write gen+pkt, seq++ (even=stable)
//   Reader (XDP): read seq1, check even, verify gen, copy pkt, read seq2, check seq1==seq2
struct cache_entry {
    __u32 seq;                   // Seqlock counter (even=stable, odd=write-in-progress)
    __u32 gen;                   // Generation counter (must match cache_value.gen)
    __u8 pkt[ARENA_ENTRY_SIZE]; // Flat DNS packet (512 bytes max)
};

struct cache_value {
    __u32 arena_idx;
    __u16 pkt_len;
    __u8  scope;
    __u8  _pad;
    __u64 expire_ts;
    __u32 gen;           // Must match cache_entries[arena_idx].gen (detects slot reuse)
    __u32 _pad2;
};  // 24 bytes

struct dns_event {
    __u64 timestamp;
    __u32 len;
    __u8 payload[];
};
