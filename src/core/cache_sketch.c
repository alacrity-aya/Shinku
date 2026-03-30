// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_ops_internal.h"

static inline uint32_t cm_index(uint64_t fp, uint32_t row, uint32_t width) {
    uint64_t mixed = fp ^ (CACHE_FREQ_ROW_SALT * (uint64_t)(row + 1U));
    return (uint32_t)(mixed % width);
}

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
