#pragma once
#ifndef __VMLINUX_H__
    #include <linux/types.h>
#endif

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
