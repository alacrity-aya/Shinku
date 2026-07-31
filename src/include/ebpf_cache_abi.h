// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#ifndef __VMLINUX_H__
    #include <linux/types.h>
    #include <stddef.h>
#endif

#define SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES 512U
#define SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS 45U
#define SHINKU_EBPF_CACHE_SLOT_ALIGNMENT 8U
#define SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE 640U

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

struct ebpf_cache_hit_scratch {
    struct ebpf_cache_slot_header header;
    __u8 response[SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES];
    __u16 ttl_offsets[SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS];
};

#if defined(__cplusplus)
[[nodiscard]] inline bool operator==(const ebpf_cache_physical_key& lhs, const ebpf_cache_physical_key& rhs) noexcept {
    return lhs.destination_ipv4 == rhs.destination_ipv4 && lhs.destination_port == rhs.destination_port
        && lhs.reserved == rhs.reserved && lhs.fingerprint.first == rhs.fingerprint.first
        && lhs.fingerprint.second == rhs.fingerprint.second;
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
SHINKU_ABI_ASSERT(sizeof(struct ebpf_cache_hit_scratch) == SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE);

    #undef SHINKU_ABI_ALIGNOF
    #undef SHINKU_ABI_ASSERT
#endif
