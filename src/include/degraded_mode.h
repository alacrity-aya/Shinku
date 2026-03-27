// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <assert.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @file degraded_mode.h
 * @brief Degraded mode state machine for failure-mode policy.
 *
 * This module implements a deterministic degradation activation system based
 * on streak thresholds. When certain failure conditions persist beyond their
 * threshold, the system enters degraded mode and exports the state via metrics.
 *
 * Design principles:
 *   - No locking in hot path (relaxed atomics only)
 *   - Bounded integer threshold checks
 *   - No extra allocations in fast path
 */

/* ============================================================================
 * Threshold Configuration
 * ============================================================================ */

/** @brief Poll events count considered as "high load" per poll */
#define SHINKU_LAG_POLL_HIGH_WATERMARK 256

/** @brief Consecutive high-load polls before activating degraded mode */
#define SHINKU_LAG_STREAK_THRESHOLD 5

/** @brief Consecutive cache map update failures before degrading */
#define SHINKU_CACHE_MAP_FAIL_STREAK_THRESHOLD 32

/** @brief Consecutive cleanup failures before degrading */
#define SHINKU_CLEANUP_FAIL_STREAK_THRESHOLD 3

/** @brief Cache line size for alignment */
#define DEGRADED_CACHELINE_SIZE 64

static_assert(
    sizeof(atomic_uint_fast64_t) <= DEGRADED_CACHELINE_SIZE,
    "degraded u64 atomic larger than cache line"
);
static_assert(
    sizeof(atomic_uint) <= DEGRADED_CACHELINE_SIZE,
    "degraded uint atomic larger than cache line"
);

/* ============================================================================
 * Aligned Counter Types
 * ============================================================================ */

/**
 * @struct degraded_aligned_u64_counter
 * @brief Cache-line aligned 64-bit atomic counter.
 */
struct degraded_aligned_u64_counter {
    alignas(DEGRADED_CACHELINE_SIZE) atomic_uint_fast64_t value; /**< Counter value */
    uint8_t pad[DEGRADED_CACHELINE_SIZE - sizeof(atomic_uint_fast64_t)]; /**< Padding */
};

/**
 * @struct degraded_aligned_uint_counter
 * @brief Cache-line aligned 32-bit atomic counter.
 */
struct degraded_aligned_uint_counter {
    alignas(DEGRADED_CACHELINE_SIZE) atomic_uint value; /**< Counter value */
    uint8_t pad[DEGRADED_CACHELINE_SIZE - sizeof(atomic_uint)]; /**< Padding */
};

/* ============================================================================
 * Degraded Reason Flags
 * ============================================================================ */

/**
 * @enum degraded_reason_flag
 * @brief Bitmask flags for degraded mode reasons.
 *
 * Multiple reasons can be active simultaneously (bitwise OR).
 */
enum degraded_reason_flag {
    DEGRADED_REASON_USERSPACE_LAG = 1u << 0,          /**< Userspace poll lag */
    DEGRADED_REASON_CLEANUP_FAILURE = 1u << 1,        /**< Cleanup thread failures */
    DEGRADED_REASON_STARTUP_ATTACH_RETRY = 1u << 2,   /**< XDP/TC attach retries */
    DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE = 1u << 3, /**< Cache map update failures */
};

/* ============================================================================
 * Degraded State Structure
 * ============================================================================ */

/**
 * @struct degraded_state
 * @brief Complete degraded mode state.
 *
 * All fields are cache-line aligned to prevent false sharing during
 * concurrent updates from multiple threads.
 */
struct degraded_state {
    struct degraded_aligned_uint_counter reason_flags;    /**< Active reason flags (bitmask) */
    struct degraded_aligned_u64_counter transitions_total; /**< Total state transitions */
    struct degraded_aligned_u64_counter reason_set_total[4]; /**< Per-reason activation counts */

    struct degraded_aligned_uint_counter userspace_lag_streak;   /**< Consecutive high-load polls */
    struct degraded_aligned_uint_counter cache_map_fail_streak;  /**< Consecutive update failures */
    struct degraded_aligned_uint_counter cleanup_fail_streak;    /**< Consecutive cleanup failures */
};

/* ============================================================================
 * Core Functions
 * ============================================================================ */

/**
 * @brief Initialize degraded state structure.
 * @param state Pointer to state structure to initialize.
 * @note All counters and flags are set to zero.
 */
void degraded_state_init(struct degraded_state* state);

/**
 * @brief Set a degraded reason flag.
 * @param state Degraded state structure.
 * @param reason_flag Reason flag to set (from enum degraded_reason_flag).
 * @return true if this caused a transition from non-degraded to degraded.
 * @note Uses memory_order_relaxed for performance.
 */
bool degraded_set_reason(struct degraded_state* state, uint32_t reason_flag);

/**
 * @brief Clear a degraded reason flag.
 * @param state Degraded state structure.
 * @param reason_flag Reason flag to clear.
 * @return true if this caused a transition from degraded to non-degraded.
 * @note Does not clear streak counters; those reset on next success.
 */
bool degraded_clear_reason(struct degraded_state* state, uint32_t reason_flag);

/**
 * @brief Get current reason flags.
 * @param state Degraded state structure.
 * @return Current reason flags bitmask.
 */
uint32_t degraded_get_reason_flags(const struct degraded_state* state);

/**
 * @brief Check if system is in degraded mode.
 * @param state Degraded state structure.
 * @return true if any reason flag is set.
 */
bool degraded_is_active(const struct degraded_state* state);

/* ============================================================================
 * Helper Functions (Streak Tracking)
 * ============================================================================ */

/**
 * @brief Note poll load for lag streak tracking.
 * @param state Degraded state structure.
 * @param poll_events Number of events returned by this poll.
 *
 * If poll_events >= SHINKU_LAG_POLL_HIGH_WATERMARK, increments lag streak.
 * Otherwise, resets streak to zero.
 *
 * Activates DEGRADED_REASON_USERSPACE_LAG when streak reaches threshold.
 */
void degraded_note_poll_load(struct degraded_state* state, int poll_events);

/**
 * @brief Note cache map update result for failure streak tracking.
 * @param state Degraded state structure.
 * @param update_ok Non-zero if update succeeded, zero if failed.
 *
 * Increments streak on failure, resets on success.
 * Activates DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE at threshold.
 */
void degraded_note_cache_map_update(struct degraded_state* state, int update_ok);

/**
 * @brief Note cleanup result for failure streak tracking.
 * @param state Degraded state structure.
 * @param cleanup_result Result from cleanup (negative = failure, >=0 = success).
 *
 * Increments streak on failure, resets on success.
 * Activates DEGRADED_REASON_CLEANUP_FAILURE at threshold.
 */
void degraded_note_cleanup_result(struct degraded_state* state, int cleanup_result);