// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file cache_types.h
 * @brief Shared type definitions for cache operations.
 *
 * Contains structures for admission policy, frequency tracking,
 * and hot/cold segmentation used across cache modules.
 */

#include "obs_metrics.h"
#include "types.h"
#include <pthread.h>
#include <stdint.h>

/**
 * @brief Cache admission policy configuration.
 *
 * Controls which responses are accepted into the cache.
 */
struct cache_admission_policy {
    uint8_t enabled; /**< Nonzero if admission policy is active */
    uint8_t pressure_mode; /**< Nonzero to enable frequency-based rejection */
    uint32_t min_ttl; /**< Minimum TTL threshold for admission */
    uint64_t dampen_window_ns; /**< Dampening window for recent inserts (ns) */
};

/**
 * @brief Recent insert tracker for admission dampening.
 *
 * Tracks recently inserted keys to prevent redundant cache updates
 * within a configurable time window.
 */
struct cache_recent_tracker {
    struct cache_key* keys; /**< Array of tracked keys */
    uint64_t* ns_timestamps; /**< Insertion timestamps (ns) */
    uint32_t capacity; /**< Total slots in arrays */
};

/**
 * @brief Count-Min sketch for frequency estimation.
 *
 * Probabilistic data structure that estimates element frequency
 * with bounded error. Uses 4 independent hash rows.
 */
struct cache_cm_sketch {
    uint16_t* rows[CACHE_FREQ_ROWS]; /**< Counter arrays for each row */
    uint32_t width; /**< Width of each row (number of counters) */
    uint32_t epoch_ops; /**< Operations between decay cycles */
    uint32_t ops; /**< Current operation count in epoch */
};

/**
 * @brief Hot/cold segment tracker.
 *
 * Tracks classification of cache entries for eviction decisions.
 * Hot entries are preserved when possible during eviction.
 */
struct cache_segment_tracker {
    uint32_t hot_threshold; /**< Frequency threshold for hot classification */
    uint32_t hot_count; /**< Current number of hot entries */
    uint32_t cold_count; /**< Current number of cold entries */
    uint32_t* slot_hit_count; /**< Per-slot hit counters (optional) */
    uint8_t* slot_hot; /**< Per-slot hot/cold flags */
};

/**
 * @brief Cache context for a single cache instance.
 *
 * Contains all state needed for cache operations including
 * the arena allocator, hash map, and admission/eviction policy.
 */
struct cache_context {
    struct cache_entry* entries; /**< Arena entries array */
    uint32_t* next_idx; /**< Atomic next slot index */
    uint32_t max_entries; /**< Arena capacity */
    int cache_map_fd; /**< BPF hash map file descriptor */

    struct cache_key* slot_owners; /**< Current owner key per slot */
    pthread_mutex_t* slot_owners_lock; /**< Lock for slot_owners access */
    struct obs_metrics* metrics; /**< Metrics for observability */

    uint32_t next_gen; /**< Next generation number for entries */

    struct cache_admission_policy admission; /**< Admission policy config */
    struct cache_recent_tracker recent; /**< Recent insert tracker */
    struct cache_cm_sketch sketch; /**< Frequency estimation sketch */
    struct cache_segment_tracker segments; /**< Hot/cold segment tracker */
};