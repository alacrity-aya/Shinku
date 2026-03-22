// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include <stdint.h>
struct env {
    const char* interface;
    enum log_level log_level;
    uint32_t arena_pages;
    uint32_t cleanup_interval;  /* Cache cleanup interval in seconds */
    uint32_t metrics_port;      /* Prometheus/health HTTP port (localhost only) */
    uint32_t obs_enabled;       /* Userspace observability switch */
    uint32_t obs_bpf_enabled;   /* BPF counter collection switch */
    uint32_t obs_bpf_sample_mask; /* BPF sampling mask: rand32 & mask == 0 */
};

int parse_args(int argc, char** argv, struct env* env);
