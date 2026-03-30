// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "degraded_mode.h"
#include "obs_metrics.h"

struct cache_context;

struct dns_parser_runtime {
    struct obs_context* obs;
    struct degraded_state* degraded;
};

struct dns_parser_context {
    struct cache_context* cache;
    struct dns_parser_runtime* runtime;
};
