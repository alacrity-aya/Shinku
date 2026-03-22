// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "types.h"
#include "obs_metrics.h"
#include <stddef.h>
#include <stdint.h>

struct cache_ctx {
    struct cache_entry* entries; /* skel->arena->cache_entries (mmap'd) */
    uint32_t* next_idx; /* skel->arena->next_entry_idx (mmap'd) */
    uint32_t max_entries; /* CACHE_MAP_MAX_ENTRIES */
    int cache_map_fd;

    /* Reverse mapping: slot_owners[arena_idx] = cache_key that currently owns the slot.
     * Used during eviction to delete stale cache_map entries when a slot is recycled. */
    struct cache_key* slot_owners;

    /* Monotonically increasing generation counter. Each store_to_cache() gets a unique gen
     * written to both cache_entry.gen and cache_value.gen. XDP checks they match to detect
     * slot reuse between cache_map lookup and arena read. */
    uint32_t next_gen;

    struct obs_context* obs;
};

int handle_packet(void* ctx, void* data, size_t len);

/* Remove expired cache_map entries and clear their slot_owners mappings.
 * Called periodically from main loop (e.g., every 10 seconds). */
int cleanup_expired_entries(struct cache_ctx* cctx);

int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash);
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);
