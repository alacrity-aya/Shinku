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
struct cache_entry {
    __u8 pkt[ARENA_ENTRY_SIZE]; // Flat DNS packet (512 bytes max)
};

// Cache Value - stored in cache_map hash, indexes into cache_entries[]
struct cache_value {
    __u32 arena_idx;     // Index into cache_entries[] array
    __u16 pkt_len;       // Actual DNS packet length (<= ARENA_ENTRY_SIZE)
    __u8  scope;         // ECS Scope (0=global, >0=subnet-specific)
    __u8  _pad;          // Alignment padding
    __u64 expire_ts;     // Expiration timestamp (ktime nanoseconds)
};  // 16 bytes

struct dns_event {
    __u64 timestamp;
    __u32 len;
    __u8 payload[];
};
