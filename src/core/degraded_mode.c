// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "degraded_mode.h"

#include <string.h>

static int reason_index(uint32_t reason_flag) {
    switch (reason_flag) {
        case DEGRADED_REASON_USERSPACE_LAG:
            return 0;
        case DEGRADED_REASON_CLEANUP_FAILURE:
            return 1;
        case DEGRADED_REASON_STARTUP_ATTACH_RETRY:
            return 2;
        case DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE:
            return 3;
        default:
            return -1;
    }
}

void degraded_state_init(struct degraded_state* state) {
    memset(state, 0, sizeof(*state));
}

bool degraded_set_reason(struct degraded_state* state, uint32_t reason_flag) {
    if (!state)
        return false;

    uint32_t prev =
        atomic_fetch_or_explicit(&state->reason_flags.value, reason_flag, memory_order_relaxed);
    if ((prev & reason_flag) == 0) {
        int idx = reason_index(reason_flag);
        if (idx >= 0) {
            atomic_fetch_add_explicit(&state->reason_set_total[idx].value, 1, memory_order_relaxed);
        }
        atomic_fetch_add_explicit(&state->transitions_total.value, 1, memory_order_relaxed);
        return true;
    }

    return false;
}

bool degraded_clear_reason(struct degraded_state* state, uint32_t reason_flag) {
    if (!state)
        return false;

    uint32_t prev =
        atomic_fetch_and_explicit(&state->reason_flags.value, ~reason_flag, memory_order_relaxed);
    if (prev & reason_flag) {
        atomic_fetch_add_explicit(&state->transitions_total.value, 1, memory_order_relaxed);
        return true;
    }

    return false;
}

uint32_t degraded_get_reason_flags(const struct degraded_state* state) {
    if (!state)
        return 0;

    return atomic_load_explicit(&state->reason_flags.value, memory_order_relaxed);
}

bool degraded_is_active(const struct degraded_state* state) {
    return degraded_get_reason_flags(state) != 0;
}

void degraded_note_poll_load(struct degraded_state* state, int poll_events) {
    if (!state)
        return;

    if (poll_events >= SHINKU_LAG_POLL_HIGH_WATERMARK) {
        unsigned int streak =
            atomic_fetch_add_explicit(&state->userspace_lag_streak.value, 1, memory_order_relaxed)
            + 1;
        if (streak >= SHINKU_LAG_STREAK_THRESHOLD) {
            degraded_set_reason(state, DEGRADED_REASON_USERSPACE_LAG);
        }
        return;
    }

    atomic_store_explicit(&state->userspace_lag_streak.value, 0, memory_order_relaxed);
    degraded_clear_reason(state, DEGRADED_REASON_USERSPACE_LAG);
}

void degraded_note_cache_map_update(struct degraded_state* state, int update_ok) {
    if (!state)
        return;

    if (!update_ok) {
        unsigned int streak =
            atomic_fetch_add_explicit(&state->cache_map_fail_streak.value, 1, memory_order_relaxed)
            + 1;
        if (streak >= SHINKU_CACHE_MAP_FAIL_STREAK_THRESHOLD) {
            degraded_set_reason(state, DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE);
        }
        return;
    }

    atomic_store_explicit(&state->cache_map_fail_streak.value, 0, memory_order_relaxed);
    degraded_clear_reason(state, DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE);
}

void degraded_note_cleanup_result(struct degraded_state* state, int cleanup_result) {
    if (!state)
        return;

    if (cleanup_result < 0) {
        unsigned int streak =
            atomic_fetch_add_explicit(&state->cleanup_fail_streak.value, 1, memory_order_relaxed)
            + 1;
        if (streak >= SHINKU_CLEANUP_FAIL_STREAK_THRESHOLD) {
            degraded_set_reason(state, DEGRADED_REASON_CLEANUP_FAILURE);
        }
        return;
    }

    atomic_store_explicit(&state->cleanup_fail_streak.value, 0, memory_order_relaxed);
    degraded_clear_reason(state, DEGRADED_REASON_CLEANUP_FAILURE);
}
