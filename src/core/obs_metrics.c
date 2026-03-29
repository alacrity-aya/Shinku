// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

/**
 * @file obs_metrics.c
 * @brief Implementation of observability metrics collection.
 *
 * This file implements the metrics collection functions declared in obs_metrics.h.
 * All counters use relaxed atomics for performance; metric values are eventually
 * consistent with actual counts.
 */
#include "obs_metrics.h"

#include "degraded_mode.h"
#include "runtime/events.h"
#include <string.h>

/**
 * @brief Convert degraded reason flag to observability reason enum.
 * @param reason_flag Degraded reason flag from degraded_mode.h.
 * @return Corresponding obs_degraded_reason value.
 */
static enum obs_degraded_reason reason_to_obs_reason(uint32_t reason_flag) {
    switch (reason_flag) {
        case DEGRADED_REASON_USERSPACE_LAG:
            return OBS_DEGRADED_RING_BACKLOG;
        case DEGRADED_REASON_CLEANUP_FAILURE:
            return OBS_DEGRADED_CLEANUP_THREAD_DOWN;
        case DEGRADED_REASON_STARTUP_ATTACH_RETRY:
            return OBS_DEGRADED_STARTUP_ATTACH_RETRY;
        case DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE:
            return OBS_DEGRADED_CACHE_MAP_UPDATE_FAIL;
        default:
            return OBS_DEGRADED_MAX;
    }
}

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

void obs_metrics_count_negative_accept(struct obs_metrics* metrics, enum obs_negative_type type) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    if ((unsigned int)type >= OBS_NEGATIVE_MAX)
        return;

    atomic_fetch_add_explicit(
        &metrics->negative_cache_accept_total[type].value,
        1,
        memory_order_relaxed
    );
}

void obs_metrics_count_negative_reject(struct obs_metrics* metrics, enum obs_negative_type type) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    if ((unsigned int)type >= OBS_NEGATIVE_MAX)
        return;

    atomic_fetch_add_explicit(
        &metrics->negative_cache_reject_total[type].value,
        1,
        memory_order_relaxed
    );
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

void obs_metrics_mark_degraded(struct obs_metrics* metrics, enum obs_degraded_reason reason) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    uint64_t prev =
        atomic_exchange_explicit(&metrics->degraded_mode.value, 1, memory_order_relaxed);
    if (prev == 0) {
        atomic_fetch_add_explicit(
            &metrics->degraded_transition_total.value,
            1,
            memory_order_relaxed
        );
    }

    if ((unsigned int)reason < OBS_DEGRADED_MAX) {
        atomic_fetch_add_explicit(
            &metrics->degraded_reason_total[reason].value,
            1,
            memory_order_relaxed
        );
    }
}

void obs_metrics_handle_degraded_event(
    enum shinku_event_type type,
    const void* payload,
    void* user_ctx
) {
    if (!payload || !user_ctx)
        return;

    struct obs_metrics* metrics = user_ctx;
    const struct shinku_event_degraded_payload* degraded_payload = payload;
    enum obs_degraded_reason mapped = reason_to_obs_reason(degraded_payload->reason_flag);

    if ((unsigned int)mapped >= OBS_DEGRADED_MAX)
        return;

    if (type == SHINKU_EVENT_DEGRADED_REASON_SET) {
        obs_metrics_mark_degraded(metrics, mapped);
        return;
    }

    if (type == SHINKU_EVENT_DEGRADED_REASON_CLEAR) {
        if (!metrics || !metrics->cfg.enabled)
            return;

        if (degraded_payload->flags_after == 0) {
            atomic_store_explicit(&metrics->degraded_mode.value, 0, memory_order_relaxed);
        }
    }
}

void obs_metrics_count_metrics_truncated(struct obs_metrics* metrics) {
    if (!metrics || !metrics->cfg.enabled)
        return;

    atomic_fetch_add_explicit(&metrics->metrics_truncated_total.value, 1, memory_order_relaxed);
}
