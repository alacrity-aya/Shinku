// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "loader_cache_bridge.h"

#include "cache.skel.h"
#include "cache_types.h"
#include "constants.h"
#include "dns_parser.h"

#include <bpf/libbpf.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t floor_power_of_two(uint32_t value) {
    if (value == 0)
        return 0;

    uint32_t power = 1;
    while ((power << 1) != 0 && (power << 1) <= value)
        power <<= 1;
    return power;
}

static void free_admission_metadata(struct cache_context* context) {
    free(context->slot_owners);
    context->slot_owners = NULL;
    free(context->recent.keys);
    context->recent.keys = NULL;
    free(context->recent.ns_timestamps);
    context->recent.ns_timestamps = NULL;
    free(context->segments.slot_hit_count);
    context->segments.slot_hit_count = NULL;
    free(context->segments.slot_hot);
    context->segments.slot_hot = NULL;
    for (int row = 0; row < CACHE_FREQ_ROWS; row++) {
        free(context->sketch.rows[row]);
        context->sketch.rows[row] = NULL;
    }
}

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
) {
    if (bridge == NULL || skeleton == NULL || skeleton->arena == NULL || skeleton->maps.cache_map == NULL)
        return -EINVAL;

    memset(bridge, 0, sizeof(*bridge));

    const int mutex_result = pthread_mutex_init(&bridge->cache_lock, NULL);
    if (mutex_result != 0)
        return -mutex_result;

    bridge->cache_lock_initialized = true;
    bridge->cache_context.slot_owners_lock = &bridge->cache_lock;
    bridge->cache_context.entries = skeleton->arena->cache_entries;
    bridge->cache_context.next_idx = &skeleton->arena->next_entry_idx;
    bridge->cache_context.max_entries = CACHE_MAP_MAX_ENTRIES;
    bridge->cache_context.cache_map_fd = bpf_map__fd(skeleton->maps.cache_map);
    bridge->cache_context.next_gen = 0;
    bridge->cache_context.admission.enabled = admission_enabled ? 1 : 0;
    bridge->cache_context.admission.pressure_mode = pressure_mode ? 1 : 0;
    bridge->cache_context.admission.min_ttl = admission_min_ttl;
    bridge->cache_context.admission.dampen_window_ns = (uint64_t)admission_dampen_window_ms * 1000000ULL;
    bridge->cache_context.segments.hot_threshold = hot_threshold;
    bridge->cache_context.sketch.width = freq_width;
    bridge->cache_context.sketch.epoch_ops = freq_epoch_ops;
    bridge->cache_context.sketch.ops = 0;

    uint32_t normalized_width = floor_power_of_two(bridge->cache_context.sketch.width);
    if (normalized_width == 0)
        normalized_width = 1;
    bridge->cache_context.sketch.width = normalized_width;

    bridge->parser_context.cache = &bridge->cache_context;
    bridge->parser_context.runtime = &bridge->parser_runtime;
    bridge->cache_context.slot_owners = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(struct cache_key));
    bridge->cache_context.recent.capacity = CACHE_MAP_MAX_ENTRIES;
    bridge->cache_context.recent.keys = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(struct cache_key));
    bridge->cache_context.recent.ns_timestamps = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(uint64_t));
    bridge->cache_context.segments.slot_hit_count = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(uint32_t));
    bridge->cache_context.segments.slot_hot = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(uint8_t));

    int admission_metadata_ok = bridge->cache_context.slot_owners != NULL && bridge->cache_context.recent.keys != NULL
        && bridge->cache_context.recent.ns_timestamps != NULL && bridge->cache_context.segments.slot_hit_count != NULL
        && bridge->cache_context.segments.slot_hot != NULL;
    for (int row = 0; row < CACHE_FREQ_ROWS; row++) {
        bridge->cache_context.sketch.rows[row] = calloc(bridge->cache_context.sketch.width, sizeof(uint16_t));
        if (bridge->cache_context.sketch.rows[row] == NULL)
            admission_metadata_ok = 0;
    }

    if (admission_metadata_ok == 0) {
        free_admission_metadata(&bridge->cache_context);
        bridge->cache_context.recent.capacity = 0;
        bridge->cache_context.sketch.width = 0;
        bridge->cache_context.sketch.ops = 0;
        bridge->cache_context.admission.enabled = 0;
        bridge->cache_context.admission.pressure_mode = 0;
    }

    return 0;
}

void loader_cache_bridge_destroy(struct loader_cache_bridge* bridge) {
    if (bridge == NULL)
        return;

    free_admission_metadata(&bridge->cache_context);
    bridge->cache_context.slot_owners_lock = NULL;
    if (bridge->cache_lock_initialized) {
        pthread_mutex_destroy(&bridge->cache_lock);
        bridge->cache_lock_initialized = false;
    }
}

int loader_cache_bridge_cleanup(struct loader_cache_bridge* bridge) {
    if (bridge == NULL)
        return -EINVAL;
    return dns_parser_cleanup_expired_entries(&bridge->cache_context);
}

int loader_cache_bridge_packet_callback(void* context, void* data, size_t size) {
    struct loader_cache_bridge* bridge = context;
    if (bridge == NULL)
        return -EINVAL;
    return dns_parser_handle_event(&bridge->parser_context, data, size);
}
