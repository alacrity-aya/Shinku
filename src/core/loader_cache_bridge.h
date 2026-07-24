// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache_types.h"
#include "parser_runtime.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cache_bpf;

struct loader_cache_bridge {
    struct cache_context cache_context;
    struct dns_parser_runtime parser_runtime;
    struct dns_parser_context parser_context;
    pthread_mutex_t cache_lock;
    bool cache_lock_initialized;
};

int loader_cache_bridge_init(
    struct loader_cache_bridge* bridge,
    struct cache_bpf* skeleton,
    uint32_t admission_enabled,
    uint32_t pressure_mode,
    uint32_t admission_min_ttl,
    uint32_t admission_dampen_window_ms,
    uint32_t hot_threshold,
    uint32_t freq_width,
    uint32_t freq_epoch_ops
);

void loader_cache_bridge_destroy(struct loader_cache_bridge* bridge);
int loader_cache_bridge_cleanup(struct loader_cache_bridge* bridge);
int loader_cache_bridge_packet_callback(void* context, void* data, size_t size);

#ifdef __cplusplus
}
#endif
