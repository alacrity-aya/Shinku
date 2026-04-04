// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
/**
 * @file cache_recent.c
 * @brief Recent insert tracking for admission dampening.
 *
 * Tracks recently inserted cache keys to prevent redundant updates
 * within a configurable dampening window. Uses bucket-based storage
 * with LRU eviction within each bucket.
 */

#include "cache_ops_internal.h"

/**
 * @brief Check if a key was inserted recently (within dampen window).
 * @param recent Recent insert tracker structure.
 * @param dampen_window_ns Dampening window in nanoseconds.
 * @param key Cache key to check.
 * @param now_ns Current time in nanoseconds.
 * @return 1 if recently inserted, 0 otherwise.
 *
 * Uses fingerprint-based bucket lookup for O(1) average case.
 * Checks all slots in the bucket for matching keys within the window.
 */
int cache_recent_was_inserted(
    const struct cache_recent_tracker* recent,
    uint64_t dampen_window_ns,
    const struct cache_key* key,
    uint64_t now_ns
) {
    if (!recent->keys || !recent->ns_timestamps || !recent->capacity)
        return 0;
    if (!dampen_window_ns)
        return 0;

    uint64_t fp = key_fingerprint(key);
    uint32_t buckets = recent->capacity / CACHE_RECENT_BUCKETS_FACTOR;
    if (buckets == 0)
        return 0;

    uint32_t idx = (uint32_t)(fp % buckets);
    uint32_t start = idx * CACHE_RECENT_BUCKETS_FACTOR;
    uint32_t end = start + CACHE_RECENT_BUCKETS_FACTOR;

    for (uint32_t i = start; i < end; i++) {
        if (recent->ns_timestamps[i] == 0)
            continue;
        if (!keys_equal(&recent->keys[i], key))
            continue;
        if (now_ns - recent->ns_timestamps[i] <= dampen_window_ns)
            return 1;
    }
    return 0;
}

/**
 * @brief Record a recent insert in the tracking array.
 * @param recent Recent insert tracker structure.
 * @param key Cache key that was inserted.
 * @param now_ns Insertion time in nanoseconds.
 *
 * Uses bucket-based storage with LRU eviction within each bucket.
 * If the key already exists, updates its timestamp. Otherwise,
 * evicts the oldest entry in the bucket.
 */
void cache_recent_track_insert(struct cache_recent_tracker* recent, const struct cache_key* key, uint64_t now_ns) {
    if (!recent->keys || !recent->ns_timestamps || !recent->capacity)
        return;

    uint64_t fp = key_fingerprint(key);
    uint32_t buckets = recent->capacity / CACHE_RECENT_BUCKETS_FACTOR;
    if (buckets == 0)
        return;

    uint32_t idx = (uint32_t)(fp % buckets);
    uint32_t start = idx * CACHE_RECENT_BUCKETS_FACTOR;
    uint32_t end = start + CACHE_RECENT_BUCKETS_FACTOR;

    uint32_t pos = start;
    uint64_t oldest = UINT64_MAX;
    for (uint32_t i = start; i < end; i++) {
        if (recent->ns_timestamps[i] != 0 && keys_equal(&recent->keys[i], key)) {
            pos = i;
            oldest = 0;
            break;
        }
        if (recent->keys[i].name_hash == CACHE_RECENT_HASH_EMPTY_HASH
            && recent->keys[i].qtype == CACHE_RECENT_HASH_EMPTY_QTYPE)
        {
            pos = i;
            oldest = 0;
            break;
        }
        if (recent->ns_timestamps[i] < oldest) {
            oldest = recent->ns_timestamps[i];
            pos = i;
        }
    }

    recent->keys[pos] = *key;
    recent->ns_timestamps[pos] = now_ns;
}