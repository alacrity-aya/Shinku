// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file parser_runtime.h
 * @brief Parser runtime types for dependency isolation.
 *
 * Forward declarations and types shared between dns_parser.c and
 * cache_ops.c. This header breaks the circular dependency between
 * those modules.
 */

#include <stdint.h>

struct cache_context;

/**
 * @brief Runtime context for DNS parser.
 *
 * Reserved for runtime dependencies needed during packet processing.
 */
struct dns_parser_runtime {
    uint8_t reserved;
};

/**
 * @brief Full context for DNS parser operation.
 *
 * Combines cache context with runtime context for use in
 * event processing callbacks.
 */
struct dns_parser_context {
    struct cache_context* cache;        /**< Cache instance for storage */
    struct dns_parser_runtime* runtime; /**< Runtime context */
};
