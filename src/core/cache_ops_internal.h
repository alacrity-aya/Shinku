// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache_types.h"
#include "parser_runtime.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#define CACHE_SEQLOCK_STEP 1U
#define CACHE_KEY_EMPTY_HASH 0U
#define CACHE_KEY_EMPTY_QTYPE 0U
#define CACHE_ADMISSION_DEFAULT_FLAGS 0U
#define CACHE_NSEC_PER_SEC 1000000000ULL
#define CACHE_FREQ_ROW_SALT 0x9e3779b97f4a7c15ULL
#define CACHE_HASH_FNV_OFFSET_BASIS 1469598103934665603ULL
#define CACHE_HASH_FNV_PRIME 1099511628211ULL
#define CACHE_CLEANUP_BATCH_SIZE 256
#define CACHE_RECENT_BUCKETS_FACTOR 2U
#define CACHE_RECENT_HASH_EMPTY_HASH 0U
#define CACHE_RECENT_HASH_EMPTY_QTYPE 0U

static inline uint32_t ring_buffer_alloc_idx(atomic_uint* next_idx, uint32_t max_entries) {
    uint32_t idx = atomic_fetch_add_explicit(next_idx, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    return idx % max_entries;
}

static inline void seqlock_write_begin(atomic_uint* seq) {
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void seqlock_write_end(atomic_uint* seq) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_release);
}

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

static inline int keys_equal(const struct cache_key* a, const struct cache_key* b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

uint16_t cache_cm_estimate(const struct cache_cm_sketch* sketch, uint64_t fp);
void cache_cm_increment(struct cache_cm_sketch* sketch, uint64_t fp);

int cache_recent_was_inserted(
    const struct cache_recent_tracker* recent,
    uint64_t dampen_window_ns,
    const struct cache_key* key,
    uint64_t now_ns
);
void cache_recent_track_insert(struct cache_recent_tracker* recent, const struct cache_key* key, uint64_t now_ns);

void cache_segments_update_metrics(
    struct dns_parser_runtime* runtime,
    struct obs_metrics* fallback_metrics,
    const struct cache_segment_tracker* segments
);
uint8_t cache_segments_calc_slot_hot(const struct cache_segment_tracker* segments, int rehit, uint32_t cur_freq);
void cache_segments_adjust_counts(
    struct cache_segment_tracker* segments,
    int had_old,
    uint8_t old_hot,
    uint8_t new_hot,
    int replacing_distinct
);
