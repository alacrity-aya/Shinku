// SPDX-License-Identifier: GPL-2.0-only
/* Seqlock snapshot, DNS TTL aging, and cache-hit serving for the BPF program. */
#pragma once

#include "bpf/cache_bpf_state.h"

/// Scratch state shared by the response-copy and TTL-offset bpf_loop callbacks.
struct shinku_snapshot_context {
    struct packet_scratch* scratch; ///< Scratch buffer receiving the copied slot data.
    __u64 slot_offset;              ///< Byte offset of the slot within the arena.
    __u64 arena_bytes;              ///< Total arena byte size (capacity * stride).
    __u32 slot_stride;              ///< Bytes between consecutive slot starts.
    __u32 response_size;            ///< Number of response bytes to copy into the frame.
    __u32 offset_table;             ///< Byte offset of the TTL-offset table within the slot.
    __u32 invalid;                  ///< Set to 1 by a callback when a bounds check fails.
};

/**
 * @brief bpf_loop callback copying one response byte from the arena slot into the scratch frame.
 *
 * Bounds-checks the copy against the response size, slot stride, and arena
 * extent; marks the context invalid and aborts the loop on an out-of-range access.
 */
static long copy_response_callback(__u32 index, void* opaque) {
    struct shinku_snapshot_context* context = opaque;
    const __u32 byte_offset = sizeof(struct ebpf_cache_slot_header) + index;
    if (index >= context->response_size || index >= SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES
        || byte_offset >= context->slot_stride || context->slot_offset + context->slot_stride > context->arena_bytes)
    {
        context->invalid = 1;
        return 1;
    }
    __u8 __arena* slot = cache_slots + context->slot_offset;
    context->scratch->frame[SHINKU_ETH_IPV4_UDP_BYTES + index] = READ_ONCE(slot[byte_offset]);
    return 0;
}

/**
 * @brief bpf_loop callback copying one __u16 TTL offset from the slot's offset table into scratch.
 *
 * Reads the entry relative to @ref shinku_snapshot_context.offset_table; marks
 * the context invalid and aborts the loop on an out-of-range access.
 */
static long copy_ttl_offset_callback(__u32 index, void* opaque) {
    struct shinku_snapshot_context* context = opaque;
    const __u32 byte_offset = context->offset_table + (index * sizeof(__u16));
    if (index >= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS || byte_offset + sizeof(__u16) > context->slot_stride
        || context->slot_offset + context->slot_stride > context->arena_bytes)
    {
        context->invalid = 1;
        return 1;
    }
    __u8 __arena* slot = cache_slots + context->slot_offset;
    const __u16 __arena* source = (const __u16 __arena*)(slot + byte_offset);
    context->scratch->ttl_offsets[index] = READ_ONCE(*source);
    return 0;
}

/**
 * @brief Copy a slot's response bytes and TTL-offset table into @p scratch.
 *
 * Runs two bpf_loop passes (response body then TTL offsets); any callback
 * bounds failure marks the context invalid and makes this return false.
 * @param scratch Scratch buffer receiving the copied data.
 * @param slot_offset Byte offset of the slot within the arena.
 * @param arena_bytes Total arena byte size.
 * @param slot_stride Bytes between consecutive slot starts.
 * @param response_size Number of response bytes to copy.
 * @param ttl_count Number of TTL offsets to copy.
 * @param offset_table Byte offset of the TTL-offset table within the slot.
 * @return True if both copies completed in bounds.
 */
static __always_inline bool snapshot_slot(
    struct packet_scratch* scratch,
    __u64 slot_offset,
    __u64 arena_bytes,
    __u32 slot_stride,
    __u32 response_size,
    __u32 ttl_count,
    __u32 offset_table
) {
    struct shinku_snapshot_context context = {
        .scratch = scratch,
        .slot_offset = slot_offset,
        .arena_bytes = arena_bytes,
        .slot_stride = slot_stride,
        .response_size = response_size,
        .offset_table = offset_table,
        .invalid = 0,
    };
    if (bpf_loop(response_size, copy_response_callback, &context, 0) < 0 || context.invalid != 0)
        return false;
    return bpf_loop(ttl_count, copy_ttl_offset_callback, &context, 0) >= 0 && context.invalid == 0;
}

/// Scratch state shared by the TTL-patching bpf_loop callback.
struct ttl_context {
    struct packet_scratch* scratch; ///< Scratch buffer holding the assembled frame and TTL offsets.
    __u64 elapsed_seconds;          ///< Seconds elapsed since the entry was stored.
    __u32 response_size;            ///< Number of response bytes in the frame.
    __u32 invalid;                  ///< Set to 1 by the callback when a bounds check fails.
};

/**
 * @brief bpf_loop callback that ages one TTL field in the assembled frame.
 *
 * Reads the TTL offset for this index, subtracts @ref ttl_context.elapsed_seconds
 * (clamped at zero), and writes the patched value back in network byte order;
 * marks the context invalid and aborts the loop if the offset leaves the
 * response bounds.
 */
static long patch_ttl_callback(__u32 index, void* opaque) {
    struct ttl_context* context = opaque;
    if (index >= SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS) {
        context->invalid = 1;
        return 1;
    }
    const __u16 offset = context->scratch->ttl_offsets[index];
    if (offset > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES - sizeof(__be32) || offset > context->response_size
        || context->response_size - offset < sizeof(__be32))
    {
        context->invalid = 1;
        return 1;
    }
    __be32 network_ttl;
    __builtin_memcpy(&network_ttl, &context->scratch->frame[SHINKU_ETH_IPV4_UDP_BYTES + offset], sizeof(network_ttl));
    const __u32 original = bpf_ntohl(network_ttl);
    const __u32 remaining = original > context->elapsed_seconds ? original - context->elapsed_seconds : 0;
    network_ttl = bpf_htonl(remaining);
    __builtin_memcpy(&context->scratch->frame[SHINKU_ETH_IPV4_UDP_BYTES + offset], &network_ttl, sizeof(network_ttl));
    return 0;
}

/**
 * @brief Age the TTLs of the assembled response by @p elapsed_seconds.
 * @param scratch Scratch buffer with the frame and TTL offsets.
 * @param response_size Number of response bytes in the frame.
 * @param ttl_count Number of TTL offsets to patch.
 * @param elapsed_seconds Seconds to subtract from each TTL.
 * @return True if every TTL was patched in bounds.
 */
static __always_inline bool
patch_ttls(struct packet_scratch* scratch, __u32 response_size, __u32 ttl_count, __u64 elapsed_seconds) {
    struct ttl_context context = {
        .scratch = scratch,
        .elapsed_seconds = elapsed_seconds,
        .response_size = response_size,
        .invalid = 0,
    };
    return bpf_loop(ttl_count, patch_ttl_callback, &context, 0) >= 0 && context.invalid == 0;
}

/**
 * @brief Compute the one's-complement IPv4 header checksum for a 20-byte header.
 * @param ip The IPv4 header (must have ihl == 5).
 * @return The checksum in network byte order.
 */
static __always_inline __sum16 ipv4_checksum(const struct iphdr* ip) {
    const __u8* bytes = (const __u8*)ip;
    __u32 sum = 0;
#pragma clang loop unroll(full)
    for (int index = 0; index < 20; index += 2)
        sum += ((__u16)bytes[index] << 8) | bytes[index + 1];
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

/**
 * @brief Serve a cached response for a query via XDP_TX, or decline with XDP_PASS.
 *
 * Reads the publication's arena slot under a seqlock (even sequence), copies the
 * response and TTL offsets into the scratch frame, ages the TTLs, rebuilds a fresh
 * Ethernet/IPv4/UDP/DNS frame with swapped source/destination and the query's
 * transaction id, and returns XDP_TX. Declines with XDP_PASS whenever the slot is
 * mid-update, stale, expired, or the frame cannot be constructed in bounds.
 * @param context The XDP packet context (buffer loads and tail adjust).
 * @param query The parsed query envelope (source of the transaction id).
 * @param question Parsed question facts (size of the preserved question section).
 * @param scratch Scratch buffer where the response frame is assembled.
 * @param publication The cache-map publication pointing at the arena slot.
 * @return XDP_TX on success, otherwise XDP_PASS (or XDP_DROP on a tail race).
 */
static __always_inline int serve_hit(
    struct xdp_md* context,
    const struct packet_view* query,
    const struct question_facts* question,
    struct packet_scratch* scratch,
    const struct ebpf_cache_publication* publication
) {
    const __u32 slot_index = READ_ONCE(publication->slot_index);
    const __u64 published_generation = READ_ONCE(publication->generation);
    const __u32 capacity = shinku_config.cache_layout.entry_capacity;
    const __u32 stride = shinku_config.cache_layout.slot_stride;
    const __u64 arena_bytes = (__u64)capacity * stride;
    if (slot_index >= capacity || stride == 0 || stride > SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE)
        return XDP_PASS;
    const __u64 slot_offset = (__u64)slot_index * stride;
    if (slot_offset + stride > arena_bytes)
        return XDP_PASS;

    __u8 __arena* slot = cache_slots + slot_offset;
    struct ebpf_cache_slot_header __arena* header = (struct ebpf_cache_slot_header __arena*)slot;
    const __u32 first_sequence = READ_ONCE(header->sequence);
    if ((first_sequence & 1U) != 0)
        return XDP_PASS;
    reader_barrier();

    const __u16 response_size = READ_ONCE(header->response_size);
    const __u16 ttl_count = READ_ONCE(header->ttl_offset_count);
    const __u64 generation = READ_ONCE(header->generation);
    const __u64 stored_at_ns = READ_ONCE(header->stored_at_ns);
    const __u64 expires_at_ns = READ_ONCE(header->expires_at_ns);
    if (generation != published_generation || response_size < SHINKU_DNS_HEADER_BYTES
        || response_size > shinku_config.cache_layout.response_capacity
        || response_size > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES
        || ttl_count > shinku_config.cache_layout.ttl_offset_capacity || ttl_count > SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS)
        return XDP_PASS;

    const __u32 offset_table = (sizeof(struct ebpf_cache_slot_header) + response_size + 1U) & ~1U;
    if (offset_table + (ttl_count * sizeof(__u16)) > stride)
        return XDP_PASS;
    if (!snapshot_slot(scratch, slot_offset, arena_bytes, stride, response_size, ttl_count, offset_table)) {
        return XDP_PASS;
    }

    reader_barrier();
    const __u32 second_sequence = READ_ONCE(header->sequence);
    if (first_sequence != second_sequence || (second_sequence & 1U) != 0)
        return XDP_PASS;

    const __u64 now = bpf_ktime_get_boot_ns();
    if (now < stored_at_ns || now >= expires_at_ns)
        return XDP_PASS;
    const __u64 elapsed_seconds = (now - stored_at_ns) / 1000000000ULL;
    if (!patch_ttls(scratch, response_size, ttl_count, elapsed_seconds)) {
        return XDP_PASS;
    }

    if (bpf_xdp_load_bytes(context, 0, scratch->frame, SHINKU_ETH_IPV4_UDP_BYTES) != 0)
        return XDP_PASS;
    if (bpf_xdp_load_bytes(
            context,
            SHINKU_ETH_IPV4_UDP_BYTES + SHINKU_DNS_HEADER_BYTES,
            scratch->frame + SHINKU_ETH_IPV4_UDP_BYTES + SHINKU_DNS_HEADER_BYTES,
            question->question_size
        )
        != 0)
        return XDP_PASS;

    struct ethhdr* output_eth = (struct ethhdr*)scratch->frame;
    struct iphdr* output_ip = (struct iphdr*)(scratch->frame + sizeof(*output_eth));
    struct udphdr* output_udp = (struct udphdr*)(scratch->frame + sizeof(*output_eth) + sizeof(*output_ip));
    struct dns_header* output_dns = (struct dns_header*)(scratch->frame + SHINKU_ETH_IPV4_UDP_BYTES);
    output_dns->id = query->dns->id;

    __u8 mac[SHINKU_ETH_ADDRESS_BYTES];
    __builtin_memcpy(mac, output_eth->h_dest, SHINKU_ETH_ADDRESS_BYTES);
    __builtin_memcpy(output_eth->h_dest, output_eth->h_source, SHINKU_ETH_ADDRESS_BYTES);
    __builtin_memcpy(output_eth->h_source, mac, SHINKU_ETH_ADDRESS_BYTES);
    const __be32 address = output_ip->saddr;
    output_ip->saddr = output_ip->daddr;
    output_ip->daddr = address;
    const __be16 port = output_udp->source;
    output_udp->source = output_udp->dest;
    output_udp->dest = port;

    output_ip->version = 4;
    output_ip->ihl = 5;
    output_ip->tos = 0;
    output_ip->tot_len = bpf_htons(sizeof(*output_ip) + sizeof(*output_udp) + response_size);
    output_ip->id = 0;
    output_ip->frag_off = bpf_htons(0x4000U);
    output_ip->ttl = 64;
    output_ip->protocol = IPPROTO_UDP;
    output_ip->check = 0;
    output_ip->check = ipv4_checksum(output_ip);
    output_udp->len = bpf_htons(sizeof(*output_udp) + response_size);
    output_udp->check = 0;

    const __u32 frame_size = SHINKU_ETH_IPV4_UDP_BYTES + response_size;
    const __u64 packet_size = bpf_xdp_get_buff_len(context);
    if (packet_size > 0x7fffffffULL)
        return XDP_PASS;
    if (bpf_xdp_adjust_tail(context, (int)frame_size - (int)packet_size) != 0) {
        return XDP_PASS;
    }

    void* data = (void*)(long)context->data;
    void* data_end = (void*)(long)context->data_end;
    if ((__u8*)data + frame_size > (__u8*)data_end)
        return XDP_DROP;
    if (bpf_xdp_store_bytes(context, 0, scratch->frame, frame_size) != 0)
        return XDP_DROP;
    return XDP_TX;
}
