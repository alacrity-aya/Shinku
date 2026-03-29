// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "dns_parser.h"

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

int dns_cache_store_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
);

int dns_cache_store_raw_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* pkt_buf,
    int pkt_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
);

int dns_cache_cleanup_expired_entries(struct cache_context* cache_ctx);
