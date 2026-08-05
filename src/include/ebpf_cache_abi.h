// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#ifndef __VMLINUX_H__
    #include <linux/types.h>
    #include <stddef.h>
#endif

/* Primitive sizing inputs: these define the ABI and cannot be derived from any
 * struct — they size the fixed arrays inside the layout structs below. */
#define SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES 512U
#define SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS 45U

/* Bit flag/mask for the pending-query state word; independent of struct layout. */
#define SHINKU_EBPF_PENDING_CLAIMED (1ULL << 63)
#define SHINKU_EBPF_PENDING_TIME_MASK (SHINKU_EBPF_PENDING_CLAIMED - 1ULL)

struct ebpf_cache_fingerprint {
    __u64 first;
    __u64 second;
};

struct ebpf_cache_secret {
    __u64 first;
    __u64 second;
};

struct ebpf_cache_physical_key {
    __be32 destination_ipv4;
    __be16 destination_port;
    __u16 reserved;
    struct ebpf_cache_fingerprint fingerprint;
};

struct ebpf_cache_publication {
    __u32 slot_index;
    __u32 reserved;
    __u64 generation;
};

struct ebpf_cache_slot_header {
    __u32 sequence;
    __u16 response_size;
    __u16 ttl_offset_count;
    __u64 generation;
    __u64 stored_at_ns;
    __u64 expires_at_ns;
};

struct ebpf_cache_bpf_layout {
    __u32 entry_capacity;
    __u32 response_capacity;
    __u32 ttl_offset_capacity;
    __u32 slot_stride;
};
//NOLINTBEGIN
struct ebpf_cache_hit_scratch {
    struct ebpf_cache_slot_header header;
    __u8 response[SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES];
    __u16 ttl_offsets[SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS];
};

struct ebpf_pending_query_key {
    __be32 source_ipv4;
    __be32 destination_ipv4;
    __be16 source_port;
    __be16 destination_port;
    __be16 transaction_id;
    __u16 reserved;
};

struct ebpf_pending_query_value {
    struct ebpf_cache_fingerprint fingerprint;
    __u64 state_and_last_seen_ns;
};

struct ebpf_correlated_dns_event {
    __u64 response_observed_at_ns;
    __be32 destination_ipv4;
    __be16 destination_port;
    __be16 response_size;
    __u8 response[SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES];
};

//NOLINTEND

struct ebpf_skeleton_rodata_config {
    struct ebpf_cache_bpf_layout cache_layout;
    struct ebpf_cache_secret secret;
    __u64 pending_timeout_ns;
};

/* Derived layout constants: reverse-derived from the structs above so a layout
 * tweak cannot silently desync a constant from the real offsets/sizes. The
 * concrete values (8 / 640 / 16 / 528) follow from the member offsets pinned
 * by the ABI asserts below. __builtin_offsetof keeps these valid even in the
 * __VMLINUX_H__ BPF context, where <stddef.h> is not included. */
#if defined(__cplusplus)
    #define SHINKU_EBPF_CACHE_SLOT_ALIGNMENT alignof(struct ebpf_cache_slot_header)
#else
    #define SHINKU_EBPF_CACHE_SLOT_ALIGNMENT _Alignof(struct ebpf_cache_slot_header)
#endif
#define SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE sizeof(struct ebpf_cache_hit_scratch)
#define SHINKU_EBPF_CORRELATED_EVENT_HEADER_BYTES __builtin_offsetof(struct ebpf_correlated_dns_event, response)
#define SHINKU_EBPF_CORRELATED_EVENT_BYTES sizeof(struct ebpf_correlated_dns_event)

#if defined(__cplusplus)
[[nodiscard]] inline bool operator==(const ebpf_cache_physical_key& lhs, const ebpf_cache_physical_key& rhs) noexcept {
    return lhs.destination_ipv4 == rhs.destination_ipv4 && lhs.destination_port == rhs.destination_port
        && lhs.reserved == rhs.reserved && lhs.fingerprint.first == rhs.fingerprint.first
        && lhs.fingerprint.second == rhs.fingerprint.second;
}

[[nodiscard]] inline bool operator==(const ebpf_pending_query_key& lhs, const ebpf_pending_query_key& rhs) noexcept {
    return lhs.source_ipv4 == rhs.source_ipv4 && lhs.destination_ipv4 == rhs.destination_ipv4
        && lhs.source_port == rhs.source_port && lhs.destination_port == rhs.destination_port
        && lhs.transaction_id == rhs.transaction_id && lhs.reserved == rhs.reserved;
}
#endif

#ifndef __VMLINUX_H__
    #if defined(__cplusplus)
        #define SHINKU_ABI_ASSERT(condition) static_assert(condition)
        #define SHINKU_ABI_ALIGNOF(type) alignof(type)
    #else
        #define SHINKU_ABI_ASSERT(condition) _Static_assert(condition, #condition)
        #define SHINKU_ABI_ALIGNOF(type) _Alignof(type)
    #endif

SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_fingerprint) == 16);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_secret) == 16);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_physical_key) == 24);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_cache_physical_key) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_physical_key, destination_ipv4) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_physical_key, destination_port) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_physical_key, reserved) == 6);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_physical_key, fingerprint) == 8);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_publication) == 16);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_cache_publication) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_publication, slot_index) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_publication, reserved) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_publication, generation) == 8);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_slot_header) == 32);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_cache_slot_header) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, sequence) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, response_size) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, ttl_offset_count) == 6);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, generation) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, stored_at_ns) == 16);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_slot_header, expires_at_ns) == 24);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_bpf_layout) == 16);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_cache_bpf_layout) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_bpf_layout, entry_capacity) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_bpf_layout, response_capacity) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_bpf_layout, ttl_offset_capacity) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_cache_bpf_layout, slot_stride) == 12);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_pending_query_key) == 16);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_pending_query_key) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, source_ipv4) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, destination_ipv4) == 4);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, source_port) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, destination_port) == 10);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, transaction_id) == 12);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_key, reserved) == 14);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_pending_query_value) == 24);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_pending_query_value) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_value, fingerprint) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_pending_query_value, state_and_last_seen_ns) == 16);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_correlated_dns_event) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_correlated_dns_event, response_observed_at_ns) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_correlated_dns_event, destination_ipv4) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_correlated_dns_event, destination_port) == 12);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_correlated_dns_event, response_size) == 14);
SHINKU_ABI_ASSERT(sizeof(struct ebpf_skeleton_rodata_config) == 40);
SHINKU_ABI_ASSERT(SHINKU_ABI_ALIGNOF(struct ebpf_skeleton_rodata_config) == 8);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_skeleton_rodata_config, cache_layout) == 0);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_skeleton_rodata_config, secret) == 16);
SHINKU_ABI_ASSERT(offsetof(struct ebpf_skeleton_rodata_config, pending_timeout_ns) == 32);

    #undef SHINKU_ABI_ALIGNOF
    #undef SHINKU_ABI_ASSERT
#endif
