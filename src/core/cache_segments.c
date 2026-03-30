// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_ops_internal.h"

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

uint8_t cache_segments_calc_slot_hot(const struct cache_segment_tracker* segments, int rehit, uint32_t cur_freq) {
    if (rehit)
        return 1;
    if (segments->hot_threshold > 0)
        return cur_freq >= segments->hot_threshold ? 1 : 0;
    return 0;
}

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
