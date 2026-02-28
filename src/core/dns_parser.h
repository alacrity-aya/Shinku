#pragma once

#include "types.h"
#include <stddef.h>
#include <stdint.h>

struct cache_ctx {
    struct cache_entry* entries; /* skel->arena->cache_entries (mmap'd) */
    uint32_t* next_idx;          /* skel->arena->next_entry_idx (mmap'd) */
    uint32_t max_entries;         /* CACHE_MAP_MAX_ENTRIES */
    int cache_map_fd;
};

int handle_packet(void* ctx, void* data, size_t len);

int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash);
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);
