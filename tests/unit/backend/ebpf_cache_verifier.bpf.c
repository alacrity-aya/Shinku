// SPDX-License-Identifier: GPL-2.0-only
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "bpf/arena/bpf_arena_common.h"
#include "ebpf_cache_abi.h"
#include "ebpf_cache_fingerprint.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, 3);
    __uint(map_flags, BPF_F_MMAPABLE);
#ifdef __TARGET_ARCH_arm64
    __ulong(map_extra, 0x1ull << 32);
#else
    __ulong(map_extra, 0x1ull << 44);
#endif
} verifier_arena SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct ebpf_cache_physical_key);
    __type(value, struct ebpf_cache_publication);
} verifier_cache_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ebpf_cache_hit_scratch);
} verifier_scratch SEC(".maps");

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
__u8 __arena verifier_slots[16 * SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE];
#else
__u8 verifier_slots[16 * SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE] SEC(".addr_space.1");
#endif

const volatile struct ebpf_cache_secret verifier_secret = {
    .first = 0x0706050403020100ULL,
    .second = 0x0f0e0d0c0b0a0908ULL,
};

const volatile struct ebpf_cache_bpf_layout verifier_layout = {
    .entry_capacity = 16,
    .response_capacity = SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES,
    .ttl_offset_capacity = SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS,
    .slot_stride = SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE,
};

static __always_inline void reader_barrier(void) {
    asm volatile("" ::: "memory");
}

static __always_inline __u32 read_network_u32(const __u8* bytes) {
    return ((__u32)bytes[0] << 24U) | ((__u32)bytes[1] << 16U) | ((__u32)bytes[2] << 8U) | bytes[3];
}

static __always_inline void write_network_u32(__u8* bytes, __u32 value) {
    bytes[0] = (__u8)(value >> 24U);
    bytes[1] = (__u8)(value >> 16U);
    bytes[2] = (__u8)(value >> 8U);
    bytes[3] = (__u8)value;
}

struct ttl_patch_context {
    struct ebpf_cache_hit_scratch* scratch;
    __u64 elapsed_seconds;
    __u32 response_size;
    __u32 invalid_offset;
};

static long patch_ttl_callback(__u32 index, void* opaque_context) {
    struct ttl_patch_context* context = opaque_context;
    if (index >= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS) {
        context->invalid_offset = 1;
        return 1;
    }

    const __u16 offset = context->scratch->ttl_offsets[index];
    if (offset > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES - sizeof(__u32)
        || (__u32)offset + sizeof(__u32) > context->response_size)
    {
        context->invalid_offset = 1;
        return 1;
    }

    __u8* ttl_bytes = &context->scratch->response[offset];
    const __u32 ttl = read_network_u32(ttl_bytes);
    const __u64 elapsed_seconds = context->elapsed_seconds;
    write_network_u32(ttl_bytes, ttl > elapsed_seconds ? ttl - elapsed_seconds : 0);
    return 0;
}

static __always_inline bool
patch_ttls(struct ebpf_cache_hit_scratch* scratch, __u32 response_size, __u32 ttl_offset_count, __u64 elapsed_seconds) {
    struct ttl_patch_context context = {
        .scratch = scratch,
        .elapsed_seconds = elapsed_seconds,
        .response_size = response_size,
        .invalid_offset = 0,
    };
    const long result = bpf_loop(ttl_offset_count, patch_ttl_callback, &context, 0);
    return result >= 0 && context.invalid_offset == 0;
}

struct slot_snapshot_context {
    struct ebpf_cache_hit_scratch* scratch;
    __u64 slot_offset;
    __u32 slot_stride;
    __u32 offset_table;
    __u32 invalid_access;
};

static long copy_response_byte_callback(__u32 index, void* opaque_context) {
    struct slot_snapshot_context* context = opaque_context;
    const __u32 byte_offset = sizeof(struct ebpf_cache_slot_header) + index;
    if (index >= SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES || byte_offset >= context->slot_stride
        || context->slot_offset + context->slot_stride > sizeof(verifier_slots))
    {
        context->invalid_access = 1;
        return 1;
    }

    __u8 __arena* slot = verifier_slots + context->slot_offset;
    context->scratch->response[index] = READ_ONCE(slot[byte_offset]);
    return 0;
}

static long copy_ttl_offset_callback(__u32 index, void* opaque_context) {
    struct slot_snapshot_context* context = opaque_context;
    const __u32 byte_offset = context->offset_table + index * sizeof(__u16);
    if (index >= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS
        || context->offset_table > sizeof(struct ebpf_cache_slot_header) + SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES
        || byte_offset + sizeof(__u16) > context->slot_stride
        || context->slot_offset + context->slot_stride > sizeof(verifier_slots))
    {
        context->invalid_access = 1;
        return 1;
    }

    __u8 __arena* slot = verifier_slots + context->slot_offset;
    const __u16 __arena* ttl_offset = (const __u16 __arena*)(slot + byte_offset);
    context->scratch->ttl_offsets[index] = READ_ONCE(*ttl_offset);
    return 0;
}

static __always_inline bool snapshot_slot(
    struct ebpf_cache_hit_scratch* scratch,
    __u64 slot_offset,
    __u32 slot_stride,
    __u32 offset_table,
    __u32 response_size,
    __u32 ttl_offset_count
) {
    struct slot_snapshot_context context = {
        .scratch = scratch,
        .slot_offset = slot_offset,
        .slot_stride = slot_stride,
        .offset_table = offset_table,
        .invalid_access = 0,
    };
    const long response_result = bpf_loop(response_size, copy_response_byte_callback, &context, 0);
    if (response_result < 0 || context.invalid_access != 0)
        return false;

    const long offset_result = bpf_loop(ttl_offset_count, copy_ttl_offset_callback, &context, 0);
    return offset_result >= 0 && context.invalid_access == 0;
}

static __always_inline bool fingerprint_packet(
    struct xdp_md* context,
    struct ebpf_cache_hit_scratch* scratch,
    struct ebpf_cache_fingerprint* fingerprint
) {
    const __u64 packet_size = bpf_xdp_get_buff_len(context);
    const __u32 size = packet_size > 255U ? 255U : (__u32)packet_size;
    if (size != 0 && bpf_xdp_load_bytes(context, 0, scratch->response, size) != 0)
        return false;

    const struct ebpf_cache_secret secret = {
        .first = verifier_secret.first,
        .second = verifier_secret.second,
    };
    *fingerprint = shinku_ebpf_cache_fingerprint(scratch->response, size, 1, 1, &secret);
    return true;
}

SEC("xdp")
int fingerprint_verifier(struct xdp_md* context) {
    const __u32 zero = 0;
    struct ebpf_cache_hit_scratch* scratch = bpf_map_lookup_elem(&verifier_scratch, &zero);
    if (!scratch)
        return XDP_ABORTED;

    struct ebpf_cache_fingerprint result;
    if (!fingerprint_packet(context, scratch, &result))
        return XDP_ABORTED;
    return result.first == result.second ? XDP_DROP : XDP_PASS;
}

SEC("xdp")
int ttl_patch_verifier(struct xdp_md* context) {
    (void)context;
    const __u32 zero = 0;
    struct ebpf_cache_hit_scratch* scratch = bpf_map_lookup_elem(&verifier_scratch, &zero);
    if (!scratch)
        return XDP_ABORTED;

    (void)patch_ttls(scratch, SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES, SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS, 1);
    return XDP_PASS;
}

SEC("xdp")
int combined_hit_verifier(struct xdp_md* context) {
    const __u32 zero = 0;
    struct ebpf_cache_hit_scratch* scratch = bpf_map_lookup_elem(&verifier_scratch, &zero);
    if (!scratch)
        return XDP_ABORTED;

    struct ebpf_cache_fingerprint fingerprint;
    if (!fingerprint_packet(context, scratch, &fingerprint))
        return XDP_PASS;
    struct ebpf_cache_physical_key key = {
        .destination_ipv4 = 0,
        .destination_port = 0,
        .reserved = 0,
        .fingerprint = fingerprint,
    };
    const struct ebpf_cache_publication* publication = bpf_map_lookup_elem(&verifier_cache_map, &key);
    if (!publication)
        return XDP_PASS;

    const __u32 slot_index = READ_ONCE(publication->slot_index);
    const __u64 published_generation = READ_ONCE(publication->generation);
    if (slot_index >= verifier_layout.entry_capacity)
        return XDP_PASS;

    const __u64 slot_offset = (__u64)slot_index * verifier_layout.slot_stride;
    if (verifier_layout.slot_stride == 0 || verifier_layout.slot_stride > SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE
        || slot_offset + verifier_layout.slot_stride > sizeof(verifier_slots))
        return XDP_PASS;

    __u8 __arena* slot = verifier_slots + slot_offset;
    struct ebpf_cache_slot_header __arena* header = (struct ebpf_cache_slot_header __arena*)slot;
    const __u32 first_sequence = READ_ONCE(header->sequence);
    if ((first_sequence & 1U) != 0)
        return XDP_PASS;
    reader_barrier();

    const __u16 response_size = READ_ONCE(header->response_size);
    const __u16 ttl_offset_count = READ_ONCE(header->ttl_offset_count);
    const __u64 generation = READ_ONCE(header->generation);
    const __u64 stored_at_ns = READ_ONCE(header->stored_at_ns);
    const __u64 expires_at_ns = READ_ONCE(header->expires_at_ns);

    scratch->header.response_size = response_size;
    scratch->header.ttl_offset_count = ttl_offset_count;
    scratch->header.generation = generation;
    scratch->header.stored_at_ns = stored_at_ns;
    scratch->header.expires_at_ns = expires_at_ns;

    if (generation != published_generation || response_size == 0 || response_size > verifier_layout.response_capacity
        || response_size > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES
        || ttl_offset_count > verifier_layout.ttl_offset_capacity
        || ttl_offset_count > SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS)
        return XDP_PASS;

    const __u32 offset_table = (sizeof(struct ebpf_cache_slot_header) + response_size + 1U) & ~1U;
    const __u32 active_size = offset_table + ttl_offset_count * sizeof(__u16);
    if (active_size > verifier_layout.slot_stride)
        return XDP_PASS;

    if (!snapshot_slot(
            scratch,
            slot_offset,
            verifier_layout.slot_stride,
            offset_table,
            response_size,
            ttl_offset_count
        ))
        return XDP_PASS;

    reader_barrier();
    const __u32 second_sequence = READ_ONCE(header->sequence);
    if (first_sequence != second_sequence || (second_sequence & 1U) != 0)
        return XDP_PASS;

    const __u64 now = bpf_ktime_get_boot_ns();
    if (now >= expires_at_ns || now < stored_at_ns)
        return XDP_PASS;
    const __u64 elapsed_seconds = (now - stored_at_ns + 999999999ULL) / 1000000000ULL;

    if (!patch_ttls(scratch, response_size, ttl_offset_count, elapsed_seconds))
        return XDP_PASS;

    const __u64 packet_size = bpf_xdp_get_buff_len(context);
    if (packet_size > 0x7fffffffULL)
        return XDP_PASS;
    const int size_delta = (int)response_size - (int)packet_size;
    if (bpf_xdp_adjust_tail(context, size_delta) != 0)
        return XDP_PASS;
    if (bpf_xdp_store_bytes(context, 0, scratch->response, response_size) != 0)
        return XDP_PASS;
    return XDP_TX;
}
