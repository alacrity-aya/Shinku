// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
/**
 * @file cache_sketch.c
 * @brief Count-Min sketch implementation for frequency estimation.
 *
 * Uses a 4-row sketch with independent hash functions to estimate
 * key access frequency for hot/cold segmentation decisions.
 */

#include "cache_ops_internal.h"

/**
 * @brief Compute row index for Count-Min sketch.
 * @param fp Key fingerprint (64-bit hash).
 * @param row Row number (0-3).
 * @param width Sketch width.
 * @return Index into the row array.
 */
static inline uint32_t cm_index(uint64_t fp, uint32_t row, uint32_t width) {
    uint64_t mixed = fp ^ (CACHE_FREQ_ROW_SALT * (uint64_t)(row + 1U));
    return (uint32_t)(mixed % width);
}

/**
 * @brief Decay all Count-Min sketch counters by half.
 * @param sketch Sketch structure with counter arrays.
 *
 * Called periodically to age out old frequency data, preventing
 * stale entries from remaining "hot" indefinitely.
 */
static void cache_cm_decay(struct cache_cm_sketch* sketch) {
    if (!sketch->width)
        return;
    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = sketch->rows[r];
        if (!row)
            continue;
        for (uint32_t i = 0; i < sketch->width; i++)
            row[i] >>= 1;
    }
}

/**
 * @brief Estimate frequency from Count-Min sketch.
 * @param sketch Sketch structure with counter arrays.
 * @param fp Key fingerprint (64-bit hash).
 * @return Minimum count across all rows (conservative estimate).
 *
 * Returns 0 if sketch is not initialized. The minimum across rows
 * provides an upper bound on the true frequency count.
 */
uint16_t cache_cm_estimate(const struct cache_cm_sketch* sketch, uint64_t fp) {
    if (!sketch->width || !sketch->rows[0])
        return 0;

    uint16_t est = UINT16_MAX;
    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = sketch->rows[r];
        if (!row)
            return 0;
        uint32_t idx = cm_index(fp, r, sketch->width);
        if (row[idx] < est)
            est = row[idx];
    }
    return est == UINT16_MAX ? 0 : est;
}

/**
 * @brief Increment frequency counter in Count-Min sketch.
 * @param sketch Sketch structure with counter arrays.
 * @param fp Key fingerprint (64-bit hash).
 *
 * Increments all 4 row counters and triggers decay if epoch ops
 * threshold is reached. Saturates at UINT16_MAX to prevent overflow.
 */
void cache_cm_increment(struct cache_cm_sketch* sketch, uint64_t fp) {
    if (!sketch->width || !sketch->rows[0])
        return;

    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = sketch->rows[r];
        if (!row)
            continue;
        uint32_t idx = cm_index(fp, r, sketch->width);
        if (row[idx] < UINT16_MAX)
            row[idx]++;
    }

    sketch->ops++;
    if (sketch->epoch_ops > 0 && sketch->ops >= sketch->epoch_ops) {
        cache_cm_decay(sketch);
        sketch->ops = 0;
    }
}