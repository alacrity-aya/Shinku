// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache_types.h"

struct dns_parser_runtime;

/**
 * @brief Store a DNS response in cache with additional flags.
 *
 * This is the core cache storage function that implements the admission policy,
 * hot/cold segmentation, and eviction logic. It writes the flattened response
 * data to the BPF arena and updates the hash map with appropriate metadata.
 *
 * @param cache_ctx   Cache context containing map pointers and configuration.
 * @param runtime     Parser runtime dependencies.
 * @param key         Cache key (QNAME hash, QTYPE, QCLASS, optional ECS).
 * @param flat_buf    Flattened response buffer (name compression resolved).
 * @param flat_len    Length of flattened response buffer.
 * @param min_ttl     Minimum TTL to use for the cache entry.
 * @param ecs_scope   ECS scope prefix length (0 if no ECS).
 * @param flags       Additional flags (e.g., FLAG_IS_NEGATIVE for NXDOMAIN/NODATA).
 * @return 0 on success, negative errno on failure.
 */
int dns_cache_store_response_with_flags(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope,
    uint8_t flags
);

/**
 * @brief Store a DNS response in cache (convenience wrapper).
 *
 * Wrapper around dns_cache_store_response_with_flags() with flags=0.
 *
 * @param cache_ctx   Cache context containing map pointers and configuration.
 * @param runtime     Parser runtime dependencies.
 * @param key         Cache key (QNAME hash, QTYPE, QCLASS, optional ECS).
 * @param flat_buf    Flattened response buffer (name compression resolved).
 * @param flat_len    Length of flattened response buffer.
 * @param min_ttl     Minimum TTL to use for the cache entry.
 * @param ecs_scope   ECS scope prefix length (0 if no ECS).
 * @return 0 on success, negative errno on failure.
 */
int dns_cache_store_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
);

/**
 * @brief Store a raw DNS response packet in cache.
 *
 * Flattens the raw packet (resolving name compression) and stores in cache.
 * This is a convenience wrapper that handles flattening before storage.
 *
 * @param cache_ctx   Cache context containing map pointers and configuration.
 * @param runtime     Parser runtime dependencies.
 * @param key         Cache key (QNAME hash, QTYPE, QCLASS, optional ECS).
 * @param pkt_buf     Raw DNS response packet buffer.
 * @param pkt_len     Length of raw packet buffer.
 * @param min_ttl     Minimum TTL to use for the cache entry.
 * @param ecs_scope   ECS scope prefix length (0 if no ECS).
 * @return 0 on success, negative errno on failure.
 */
int dns_cache_store_raw_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* pkt_buf,
    int pkt_len,
    uint32_t min_ttl,
    uint8_t ecs_scope,
    uint8_t flags
);

/**
 * @brief Remove expired entries from the cache.
 *
 * Iterates through the cache hash map and removes entries whose TTL has expired.
 * This is typically called periodically by the cleanup thread.
 *
 * @param cache_ctx   Cache context containing map pointers.
 * @return Number of entries removed on success, negative errno on failure.
 */
int dns_cache_cleanup_expired_entries(struct cache_context* cache_ctx);
