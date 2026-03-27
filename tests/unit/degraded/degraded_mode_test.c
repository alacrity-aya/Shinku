// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "degraded_mode.h"

#include <stdio.h>

static int tests_run;
static int tests_pass;

#define TEST_ASSERT(cond, msg) \
    do { \
        tests_run++; \
        if (cond) { \
            tests_pass++; \
            printf("[PASS] %s\n", msg); \
        } else { \
            printf("[FAIL] %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void) {
    struct degraded_state st;
    degraded_state_init(&st);

    TEST_ASSERT(!degraded_is_active(&st), "fresh state not degraded");

    for (unsigned int i = 0; i < SHINKU_LAG_STREAK_THRESHOLD; i++)
        degraded_note_poll_load(&st, SHINKU_LAG_POLL_HIGH_WATERMARK);
    TEST_ASSERT(degraded_is_active(&st), "lag streak activates degraded mode");
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_USERSPACE_LAG) != 0,
        "lag reason flag set"
    );

    degraded_note_poll_load(&st, 1);
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_USERSPACE_LAG) == 0,
        "lag reason clears on healthy poll"
    );

    for (unsigned int i = 0; i < SHINKU_CACHE_MAP_FAIL_STREAK_THRESHOLD; i++)
        degraded_note_cache_map_update(&st, 0);
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE) != 0,
        "cache_map failure streak sets degraded reason"
    );

    degraded_note_cache_map_update(&st, 1);
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE) == 0,
        "cache_map degraded reason clears after success"
    );

    for (unsigned int i = 0; i < SHINKU_CLEANUP_FAIL_STREAK_THRESHOLD; i++)
        degraded_note_cleanup_result(&st, -1);
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_CLEANUP_FAILURE) != 0,
        "cleanup failure streak sets degraded reason"
    );

    degraded_note_cleanup_result(&st, 0);
    TEST_ASSERT(
        (degraded_get_reason_flags(&st) & DEGRADED_REASON_CLEANUP_FAILURE) == 0,
        "cleanup degraded reason clears after healthy cycle"
    );

    TEST_ASSERT(
        atomic_load_explicit(&st.transitions_total.value, memory_order_relaxed) > 0,
        "transitions counter increments"
    );

    printf("Total=%d Passed=%d Failed=%d\n", tests_run, tests_pass, tests_run - tests_pass);
    return 0;
}
