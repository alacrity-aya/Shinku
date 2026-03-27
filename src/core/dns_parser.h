// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "degraded_mode.h"
#include "obs_metrics.h"
#include "types.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @file dns_parser.h
 * @brief DNS packet parser and cache management.
 *
 * This module handles DNS response parsing, cache storage, and TTL-based
 * expiration. It processes DNS packets captured by BPF and stores valid
 * responses in the shared arena cache for XDP-level serving.
 */

/**
 * @struct cache_context
 * @brief Context for cache operations shared between BPF and userspace.
 *
 * This structure holds all state needed for cache management including
 * the arena memory region, BPF map file descriptor, and metadata tracking.
 */
struct cache_context {
    struct cache_entry* entries; /**< Arena array of cache entries (mmap'd from BPF) */
    uint32_t* next_idx; /**< Next arena slot index (mmap'd from BPF) */
    uint32_t max_entries; /**< Maximum entries (CACHE_MAP_MAX_ENTRIES) */
    int cache_map_fd; /**< BPF hashmap file descriptor for cache lookups */

    /**
     * @brief Reverse mapping: slot_owners[arena_idx] = cache_key.
     *
     * Used during eviction to delete stale cache_map entries when a slot
     * is recycled. Maintains O(1) reverse lookup for cleanup.
     */
    struct cache_key* slot_owners;

    /**
     * @brief Monotonically increasing generation counter.
     *
     * Each store_to_cache() gets a unique gen written to both
     * cache_entry.gen and cache_value.gen. XDP verifies they match
     * to detect slot reuse between cache_map lookup and arena read.
     */
    uint32_t next_gen;
};

/**
 * @struct dns_parser_runtime
 * @brief Runtime dependencies for parser side-effects.
 *
 * Separates parser/cache data-plane state (cache_context) from
 * cross-cutting runtime services (metrics + degraded mode).
 */
struct dns_parser_runtime {
    struct obs_context* obs; /**< Observability context for metrics */
    struct degraded_state* degraded; /**< Degraded mode state machine */
};

/**
 * @struct dns_parser_context
 * @brief Full parser callback context for ring-buffer event handling.
 */
struct dns_parser_context {
    struct cache_context* cache; /**< Cache storage context */
    struct dns_parser_runtime* runtime; /**< Runtime service dependencies */
};

/**
 * @brief Handle a DNS packet event from BPF ring buffer.
 * @param ctx Cache context (struct cache_context*).
 * @param data Pointer to dns_event structure.
 * @param len Length of event data.
 * @return 0 on success, negative on error.
 *
 * This is the main entry point for processing DNS packets captured by BPF.
 * Parses the DNS response and stores valid responses in cache.
 *
 * @note Designed as a callback for ring_buffer__new().
 */
int dns_parser_handle_event(void* ctx, void* data, size_t len);

/**
 * @brief Compatibility alias for dns_parser_handle_event.
 * @deprecated Use dns_parser_handle_event() instead.
 */
int cache_handle_event(void* ctx, void* data, size_t len);

/**
 * @brief Legacy alias for cache_handle_event.
 * @param ctx Cache context.
 * @param data Packet data.
 * @param len Packet length.
 * @return 0 on success, negative on error.
 * @deprecated Use cache_handle_event() instead.
 */
int handle_packet(void* ctx, void* data, size_t len);

/**
 * @brief Remove expired cache entries.
 * @param cache_ctx Cache context.
 * @return Number of entries removed, or negative on error.
 *
 * Iterates through cache_map, checking expire_ts against current time.
 * Removes expired entries from both cache_map and clears their
 * slot_owners mappings.
 *
 * @note Should be called periodically from main loop (e.g., every 10 seconds).
 */
int dns_parser_cleanup_expired_entries(struct cache_context* cache_ctx);

/**
 * @brief Compatibility alias for dns_parser_cleanup_expired_entries.
 * @deprecated Use dns_parser_cleanup_expired_entries() instead.
 */
int cache_cleanup_expired_entries(struct cache_context* cache_ctx);

/**
 * @brief Legacy alias for cache_cleanup_expired_entries.
 * @param cache_ctx Cache context.
 * @return Number of entries removed, or negative on error.
 * @deprecated Use cache_cleanup_expired_entries() instead.
 */
int cleanup_expired_entries(struct cache_context* cache_ctx);

/**
 * @brief Calculate FNV-1a hash of DNS name (strict mode, no compression).
 * @param packet DNS packet data.
 * @param offset Offset to start of DNS name.
 * @param max_len Maximum bytes to read.
 * @param out_hash Output: calculated hash value.
 * @return Bytes consumed, or negative on error.
 *
 * Used in XDP path where compression pointers are rejected for safety.
 * Case-insensitive (lowercases all bytes before hashing).
 */
int dns_parser_calculate_hash_strict_impl(
    const uint8_t* packet,
    int offset,
    int max_len,
    uint32_t* out_hash
);

/**
 * @brief Compatibility alias for dns_parser_calculate_hash_strict_impl.
 * @deprecated Use dns_parser_calculate_hash_strict_impl() instead.
 */
int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash);

/**
 * @brief Flatten a DNS name with compression pointer resolution.
 * @param packet DNS packet data.
 * @param offset Offset to start of DNS name.
 * @param max_len Maximum bytes to read.
 * @param dest Output buffer for flattened name.
 * @param dest_max Maximum output buffer size.
 * @return Length of flattened name, or negative on error.
 *
 * Resolves compression pointers (RFC 1035) and produces a flat,
 * uncompressed DNS name. Used in userspace path where compression
 * is allowed.
 */
int dns_parser_flatten_name_impl(
    const uint8_t* packet,
    int offset,
    int max_len,
    uint8_t* dest,
    int dest_max
);

/**
 * @brief Compatibility alias for dns_parser_flatten_name_impl.
 * @deprecated Use dns_parser_flatten_name_impl() instead.
 */
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);
