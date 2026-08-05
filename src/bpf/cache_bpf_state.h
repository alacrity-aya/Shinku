// SPDX-License-Identifier: GPL-2.0-only
/* Private maps and read-only configuration shared by the cache BPF parts. */
#pragma once

#include "bpf/cache_bpf_common.h"

const volatile struct ebpf_skeleton_rodata_config shinku_config = {};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_cache_physical_key);
    __type(value, struct ebpf_cache_publication);
} cache_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_pending_query_key);
    __type(value, struct ebpf_pending_query_value);
} pending_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SHINKU_PACKET_RING_BYTES);
} rb_pkt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_scratch);
} packet_scratch_map SEC(".maps");

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
