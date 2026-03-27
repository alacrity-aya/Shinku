// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once
#ifndef __VMLINUX_H__
    #include <linux/types.h>
    #include <stdint.h>
#endif
#include "constants.h"

/**
 * @file types.h
 * @brief Core type definitions for DNS cache system.
 *
 * This header defines the fundamental data structures used for DNS packet
 * parsing, cache storage, and BPF/userspace communication.
 */

/**
 * @struct dns_hdr
 * @brief DNS packet header (12 bytes total).
 *
 * Memory layout (each row represents 16 bits):
 * @code
 * 0                   1                   2                   3
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
 * @endcode
 */
struct dns_hdr {
    __be16 id;     /**< Transaction ID */
    __be16 flags;  /**< DNS Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE) */
    __be16 qdcount; /**< Question Count */
    __be16 ancount; /**< Answer Record Count */
    __be16 nscount; /**< Authority Record Count */
    __be16 arcount; /**< Additional Record Count */
} __attribute__((packed));

/**
 * @struct cache_key
 * @brief Cache lookup key (16 bytes).
 *
 * Used as the key for BPF hashmap lookups. The name is hashed using
 * FNV-1a algorithm for consistent lookup performance.
 */
struct cache_key {
    __u32 name_hash; /**< FNV-1a hash of DNS question name */
    __u16 qtype;     /**< Query type (A=1, AAAA=28, etc.) */
    __u16 qclass;    /**< Query class (IN=1) */
    __u32 _pad;      /**< Padding for alignment */
};

/**
 * @struct cache_entry
 * @brief Cache entry stored in BPF arena memory (520 bytes).
 *
 * Layout:
 *   - seq (4B): Seqlock counter
 *   - gen (4B): Generation counter
 *   - pkt (512B): Flat DNS response packet
 *
 * pkt[] starts at offset 8, naturally aligned for 8-byte XDP copies.
 *
 * @note Synchronization protocol (seqlock + generation):
 *   - Writer (userspace): seq++ (odd=writing), write gen+pkt, seq++ (even=stable)
 *   - Reader (XDP): read seq1, check even, verify gen, copy pkt, read seq2, check seq1==seq2
 */
struct cache_entry {
    __u32 seq;                   /**< Seqlock counter (even=stable, odd=write-in-progress) */
    __u32 gen;                   /**< Generation counter (must match cache_value.gen) */
    __u8 pkt[ARENA_ENTRY_SIZE];  /**< Flat DNS packet (512 bytes max) */
};

/**
 * @struct cache_value
 * @brief Cache metadata stored in BPF hashmap (24 bytes).
 *
 * Contains the metadata needed to locate and validate a cached response.
 * The gen field enables detection of slot reuse (ABA problem prevention).
 */
struct cache_value {
    __u32 arena_idx;  /**< Index into cache_entries arena array */
    __u16 pkt_len;    /**< Length of cached packet in bytes */
    __u8 scope;       /**< ECS scope prefix length (0 if no ECS) */
    __u8 flags;       /**< Entry flags (negative cache, nxdomain, etc.) */
    __u64 expire_ts;  /**< Expiration timestamp in nanoseconds (MONOTONIC) */
    __u32 gen;        /**< Generation counter (must match cache_entries[arena_idx].gen) */
    __u32 _pad2;      /**< Padding for alignment */
};

/** @brief Cache entry is a negative cache response (NXDOMAIN or NODATA) */
#define CACHE_VALUE_FLAG_NEGATIVE 0x1

/** @brief Cache entry is specifically an NXDOMAIN response */
#define CACHE_VALUE_FLAG_NXDOMAIN 0x2

/**
 * @struct dns_event
 * @brief DNS packet event sent from BPF to userspace via ring buffer.
 *
 * Variable-length structure containing the captured DNS packet payload.
 */
struct dns_event {
    __u64 timestamp; /**< Capture timestamp (nanoseconds) */
    __u32 len;       /**< Payload length in bytes */
    __u8 payload[];  /**< Flexible array: DNS packet data */
};