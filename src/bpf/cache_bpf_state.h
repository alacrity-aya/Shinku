// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file cache_bpf_state.h
 * @brief Private BPF maps and read-only configuration shared by the cache BPF parts.
 *
 * Declares the cache hash map, the pending-query hash map, the packet ring
 * buffer, the per-CPU scratch array, and the arena that backs the cache slot
 * storage, plus the rodata config populated at load time.
 */
#pragma once

#include "bpf/cache_bpf_common.h"

/// Read-only configuration populated by the loader at BPF load time.
const volatile struct ebpf_skeleton_rodata_config shinku_config = {};

/// Hash map from physical cache key to publication (slot index + generation).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_cache_physical_key);
    __type(value, struct ebpf_cache_publication);
} cache_map SEC(".maps");

/// Hash map from pending-query key to its fingerprint and packed state.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_pending_query_key);
    __type(value, struct ebpf_pending_query_value);
} pending_queries SEC(".maps");

/// Ring buffer carrying correlated DNS events from BPF to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SHINKU_PACKET_RING_BYTES);
} rb_pkt SEC(".maps");

/// Per-CPU array providing the scratch buffer used while assembling a response.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_scratch);
} packet_scratch_map SEC(".maps");

/// Arena map backing the cache slot storage, shared with the host store.
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
__u8 __arena cache_slots[1];
#else
__u8 cache_slots[1] SEC(".addr_space.1");
#endif
