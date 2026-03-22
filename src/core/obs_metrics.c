// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "obs_metrics.h"
#include <string.h>

void obs_metrics_init(struct obs_metrics* metrics, const struct obs_metrics_config* cfg) {
    memset(metrics, 0, sizeof(*metrics));
    metrics->cfg = *cfg;
}

void obs_metrics_count_parser_reject(
    struct obs_metrics* metrics,
    enum obs_parser_reject_reason reason
) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    atomic_fetch_add_explicit(&metrics->parser_reject_total.value, 1, memory_order_relaxed);

    if ((unsigned int)reason < OBS_REJECT_MAX) {
        atomic_fetch_add_explicit(
            &metrics->parser_reject_by_reason[reason].value,
            1,
            memory_order_relaxed
        );
    }
}

void obs_metrics_count_cache_insert(struct obs_metrics* metrics, int success) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    if (success)
        atomic_fetch_add_explicit(&metrics->cache_insert_total.value, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&metrics->cache_insert_fail_total.value, 1, memory_order_relaxed);
}

void obs_metrics_add_cleanup_removed(struct obs_metrics* metrics, uint64_t removed) {
    if (!metrics || !metrics->cfg.enabled || removed == 0)
        return;

    atomic_fetch_add_explicit(&metrics->cleanup_removed_total.value, removed, memory_order_relaxed);
}

void obs_metrics_count_rb_poll_error(struct obs_metrics* metrics) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    atomic_fetch_add_explicit(&metrics->rb_pkt_poll_error_total.value, 1, memory_order_relaxed);
}
