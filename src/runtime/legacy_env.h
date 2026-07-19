// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Temporary C runtime configuration consumed by the existing eBPF loader.
 *
 * New configuration authority lives in src/config/. This type remains only as
 * a C ABI bridge until the eBPF backend is wrapped behind the C++ Backend
 * interface.
 */
struct env {
    const char* interface;
    enum log_level log_level;
    uint32_t arena_pages;
    uint32_t cleanup_interval_ms;
    uint32_t admission_enabled;
    uint32_t pressure_mode;
    uint32_t admission_min_ttl;
    uint32_t admission_dampen_window_ms;
    uint32_t hot_threshold;
    uint32_t freq_width;
    uint32_t freq_epoch_ops;
};

#ifdef __cplusplus
}
#endif
