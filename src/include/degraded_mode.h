// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <assert.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define SHINKU_LAG_POLL_HIGH_WATERMARK 256
#define SHINKU_LAG_STREAK_THRESHOLD 5
#define SHINKU_CACHE_MAP_FAIL_STREAK_THRESHOLD 32
#define SHINKU_CLEANUP_FAIL_STREAK_THRESHOLD 3
#define DEGRADED_CACHELINE_SIZE 64

static_assert(
    sizeof(atomic_uint_fast64_t) <= DEGRADED_CACHELINE_SIZE,
    "degraded u64 atomic larger than cache line"
);
static_assert(
    sizeof(atomic_uint) <= DEGRADED_CACHELINE_SIZE,
    "degraded uint atomic larger than cache line"
);

struct degraded_aligned_u64_counter {
    alignas(DEGRADED_CACHELINE_SIZE) atomic_uint_fast64_t value;
    uint8_t pad[DEGRADED_CACHELINE_SIZE - sizeof(atomic_uint_fast64_t)];
};

struct degraded_aligned_uint_counter {
    alignas(DEGRADED_CACHELINE_SIZE) atomic_uint value;
    uint8_t pad[DEGRADED_CACHELINE_SIZE - sizeof(atomic_uint)];
};

enum degraded_reason_flag {
    DEGRADED_REASON_USERSPACE_LAG = 1u << 0,
    DEGRADED_REASON_CLEANUP_FAILURE = 1u << 1,
    DEGRADED_REASON_STARTUP_ATTACH_RETRY = 1u << 2,
    DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE = 1u << 3,
};

struct degraded_state {
    struct degraded_aligned_uint_counter reason_flags;
    struct degraded_aligned_u64_counter transitions_total;
    struct degraded_aligned_u64_counter reason_set_total[4];

    struct degraded_aligned_uint_counter userspace_lag_streak;
    struct degraded_aligned_uint_counter cache_map_fail_streak;
    struct degraded_aligned_uint_counter cleanup_fail_streak;
};

void degraded_state_init(struct degraded_state* state);
bool degraded_set_reason(struct degraded_state* state, uint32_t reason_flag);
bool degraded_clear_reason(struct degraded_state* state, uint32_t reason_flag);
uint32_t degraded_get_reason_flags(const struct degraded_state* state);
bool degraded_is_active(const struct degraded_state* state);

void degraded_note_poll_load(struct degraded_state* state, int poll_events);
void degraded_note_cache_map_update(struct degraded_state* state, int update_ok);
void degraded_note_cleanup_result(struct degraded_state* state, int cleanup_result);
