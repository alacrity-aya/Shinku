// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
/**
 * @file cache_segments.c
 * @brief Hot/cold segment management for cache entries.
 *
 * Tracks hot vs cold classification of cache entries for smarter
 * eviction decisions. Hot entries (high frequency) are preserved
 * during eviction when possible.
 */

#include "cache_ops_internal.h"

/**
 * @brief Update hot/cold segment size metrics.
 * @param runtime Parser runtime with observability context.
 * @param fallback_metrics Fallback metrics pointer if runtime is NULL.
 * @param segments Segment tracker with hot/cold counts.
 *
 * Publishes current segment sizes as Prometheus gauges.
 */
void cache_segments_update_metrics(
    struct dns_parser_runtime* runtime,
    struct obs_metrics* fallback_metrics,
    const struct cache_segment_tracker* segments
) {
    struct obs_metrics* metrics = runtime && runtime->obs ? runtime->obs->metrics : fallback_metrics;

    if (!metrics || !metrics->cfg.enabled)
        return;

    obs_metrics_set_cache_segment_sizes(metrics, segments->hot_count, segments->cold_count);
}

/**
 * @brief Determine if a slot should be marked hot.
 * @param segments Segment tracker with hot threshold config.
 * @param rehit Nonzero if this is a cache rehit (always hot).
 * @param cur_freq Current frequency estimate from Count-Min sketch.
 * @return 1 if hot, 0 if cold.
 *
 * Rehits are always marked hot. Otherwise, compare frequency against
 * configured threshold.
 */
uint8_t cache_segments_calc_slot_hot(const struct cache_segment_tracker* segments, int rehit, uint32_t cur_freq) {
    if (rehit)
        return 1;
    if (segments->hot_threshold > 0)
        return cur_freq >= segments->hot_threshold ? 1 : 0;
    return 0;
}

/**
 * @brief Adjust hot/cold segment counters during cache update.
 * @param segments Segment tracker with counters.
 * @param had_old Nonzero if replacing existing entry.
 * @param old_hot Previous entry's hot status.
 * @param new_hot New entry's hot status.
 * @param replacing_distinct Nonzero if new key differs from old.
 *
 * Handles four cases:
 * 1. New entry: increment appropriate segment counter
 * 2. Replacing distinct key: decrement old, increment new
 * 3. Same key with hot/cold transition: transfer between segments
 * 4. Same key, same hot status: no change needed
 */
void cache_segments_adjust_counts(
    struct cache_segment_tracker* segments,
    int had_old,
    uint8_t old_hot,
    uint8_t new_hot,
    int replacing_distinct
) {
    if (!segments->slot_hot)
        return;

    if (!had_old) {
        if (new_hot)
            segments->hot_count++;
        else
            segments->cold_count++;
        return;
    }

    if (replacing_distinct) {
        if (old_hot) {
            if (segments->hot_count > 0)
                segments->hot_count--;
        } else if (segments->cold_count > 0) {
            segments->cold_count--;
        }

        if (new_hot)
            segments->hot_count++;
        else
            segments->cold_count++;
        return;
    }

    if (old_hot != new_hot) {
        if (old_hot) {
            if (segments->hot_count > 0)
                segments->hot_count--;
            segments->cold_count++;
        } else {
            if (segments->cold_count > 0)
                segments->cold_count--;
            segments->hot_count++;
        }
    }
}