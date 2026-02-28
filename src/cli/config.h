// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include <stdint.h>
struct env {
    const char* interface;
    enum log_level log_level;
    uint32_t arena_pages;
};

int parse_args(int argc, char** argv, struct env* env);
