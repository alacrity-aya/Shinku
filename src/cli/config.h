#pragma once

#include "bpf_log.h"

struct env {
    const char* interface;
    enum log_level log_level;
};

int parse_args(int argc, char** argv, struct env* env);
