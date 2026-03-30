// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache_types.h"
#include "parser_runtime.h"
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
 * @brief Parse DNS name once and optionally return hash/flat/consumed outputs.
 * @param packet DNS packet data.
 * @param offset Offset to start of DNS name.
 * @param max_len Maximum bytes to read.
 * @param out_hash Optional output hash (FNV-1a, case-insensitive labels).
 * @param dest Optional output flattened name buffer.
 * @param dest_max Size of flattened output buffer.
 * @param out_consumed Optional output for wire bytes consumed at original offset.
 * @return Flattened name length, or negative on error.
 */
int dns_parser_parse_name_impl(
    const uint8_t* packet,
    int offset,
    int max_len,
    uint32_t* out_hash,
    uint8_t* dest,
    int dest_max,
    int* out_consumed
);

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
int dns_parser_calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash);

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
int dns_parser_flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);

/**
 * @brief Compatibility alias for dns_parser_flatten_name_impl.
 * @deprecated Use dns_parser_flatten_name_impl() instead.
 */
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);
