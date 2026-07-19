// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file cache_ops_internal.h
 * @brief Internal declarations for cache operations modules.
 *
 * Contains inline helpers and function declarations shared between
 * cache_sketch.c, cache_recent.c, cache_segments.c, and cache_ops.c.
 * Not for external use - external consumers should use cache_ops.h.
 */

#include "cache_types.h"
#include "parser_runtime.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/** @brief Seqlock step value for odd/even sequence detection */
#define CACHE_SEQLOCK_STEP 1U

/** @brief Sentinel hash value for empty cache keys */
#define CACHE_KEY_EMPTY_HASH 0U

/** @brief Sentinel qtype value for empty cache keys */
#define CACHE_KEY_EMPTY_QTYPE 0U

/** @brief Default flags for cache admission */
#define CACHE_ADMISSION_DEFAULT_FLAGS 0U

/** @brief Nanoseconds per second constant */
#define CACHE_NSEC_PER_SEC 1000000000ULL

/** @brief Salt for Count-Min sketch row hashing (golden ratio) */
#define CACHE_FREQ_ROW_SALT 0x9e3779b97f4a7c15ULL

/** @brief FNV-1a offset basis for fingerprint hashing */
#define CACHE_HASH_FNV_OFFSET_BASIS 1469598103934665603ULL

/** @brief FNV-1a prime for fingerprint hashing */
#define CACHE_HASH_FNV_PRIME 1099511628211ULL

/** @brief Number of entries to process per cleanup batch */
#define CACHE_CLEANUP_BATCH_SIZE 256

/** @brief Number of slots per bucket in recent tracker */
#define CACHE_RECENT_BUCKETS_FACTOR 2U

/** @brief Sentinel hash for empty recent tracker slot */
#define CACHE_RECENT_HASH_EMPTY_HASH 0U

/** @brief Sentinel qtype for empty recent tracker slot */
#define CACHE_RECENT_HASH_EMPTY_QTYPE 0U

/**
 * @brief Allocate next arena slot index using atomic fetch-and-add.
 * @param next_idx Atomic counter for next slot.
 * @param max_entries Arena capacity (wraps around).
 * @return Slot index in [0, max_entries).
 */
static inline uint32_t ring_buffer_alloc_idx(atomic_uint* next_idx, uint32_t max_entries) {
    uint32_t idx = atomic_fetch_add_explicit(next_idx, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    return idx % max_entries;
}

/**
 * @brief Begin seqlock write section (increment odd, fence).
 * @param seq Sequence counter to increment.
 *
 * Makes sequence odd to indicate write in progress. Readers will
 * detect this and retry.
 */
static inline void seqlock_write_begin(atomic_uint* seq) {
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
}

/**
 * @brief End seqlock write section (fence, increment even).
 * @param seq Sequence counter to increment.
 *
 * Makes sequence even to indicate write complete. Memory fence
 * ensures all writes are visible before sequence is updated.
 */
static inline void seqlock_write_end(atomic_uint* seq) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_release);
}

/**
 * @brief Compute 64-bit fingerprint of cache key.
 * @param key Cache key to fingerprint.
 * @return 64-bit hash value using FNV-1a.
 *
 * Used for Count-Min sketch indexing and recent tracker bucketing.
 */
static inline uint64_t key_fingerprint(const struct cache_key* key) {
    uint64_t h = CACHE_HASH_FNV_OFFSET_BASIS;
#define MIX_BYTE(v) \
    do { \
        h ^= (uint64_t)(v); \
        h *= CACHE_HASH_FNV_PRIME; \
    } while (0)
    const uint8_t* p = (const uint8_t*)key;
    for (size_t i = 0; i < sizeof(*key); i++)
        MIX_BYTE(p[i]);
#undef MIX_BYTE
    return h;
}

/**
 * @brief Compare two cache keys for equality.
 * @param a First key.
 * @param b Second key.
 * @return Nonzero if equal, zero otherwise.
 */
static inline int keys_equal(const struct cache_key* a, const struct cache_key* b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

/* Count-Min sketch functions (cache_sketch.c) */
uint16_t cache_cm_estimate(const struct cache_cm_sketch* sketch, uint64_t fp);
void cache_cm_increment(struct cache_cm_sketch* sketch, uint64_t fp);

/* Recent insert tracker functions (cache_recent.c) */
int cache_recent_was_inserted(
    const struct cache_recent_tracker* recent,
    uint64_t dampen_window_ns,
    const struct cache_key* key,
    uint64_t now_ns
);
void cache_recent_track_insert(struct cache_recent_tracker* recent, const struct cache_key* key, uint64_t now_ns);

/* Hot/cold segment functions (cache_segments.c) */
uint8_t cache_segments_calc_slot_hot(const struct cache_segment_tracker* segments, int rehit, uint32_t cur_freq);
void cache_segments_adjust_counts(
    struct cache_segment_tracker* segments,
    int had_old,
    uint8_t old_hot,
    uint8_t new_hot,
    int replacing_distinct
);
