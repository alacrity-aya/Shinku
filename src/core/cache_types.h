// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "obs_metrics.h"
#include "types.h"
#include <pthread.h>
#include <stdint.h>

struct cache_admission_policy {
    uint8_t enabled;
    uint8_t pressure_mode;
    uint32_t min_ttl;
    uint64_t dampen_window_ns;
};

struct cache_recent_tracker {
    struct cache_key* keys;
    uint64_t* ns_timestamps;
    uint32_t capacity;
};

struct cache_cm_sketch {
    uint16_t* rows[CACHE_FREQ_ROWS];
    uint32_t width;
    uint32_t epoch_ops;
    uint32_t ops;
};

struct cache_segment_tracker {
    uint32_t hot_threshold;
    uint32_t hot_count;
    uint32_t cold_count;
    uint32_t* slot_hit_count;
    uint8_t* slot_hot;
};

struct cache_context {
    struct cache_entry* entries;
    uint32_t* next_idx;
    uint32_t max_entries;
    int cache_map_fd;

    struct cache_key* slot_owners;
    pthread_mutex_t* slot_owners_lock;
    struct obs_metrics* metrics;

    uint32_t next_gen;

    struct cache_admission_policy admission;
    struct cache_recent_tracker recent;
    struct cache_cm_sketch sketch;
    struct cache_segment_tracker segments;
};
