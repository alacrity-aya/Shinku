#pragma once

#include "config.h"
#include <bpf/libbpf.h>
#include <errno.h>

struct cache_bpf;

struct bpf_ctx {
    struct cache_bpf* skel;
    struct ring_buffer* rb;
    struct log_options log_opt;
};

int setup_bpf(struct bpf_ctx* ctx, const struct env* env);
int poll_bpf(struct bpf_ctx* ctx, int timeout_ms);
void cleanup_bpf(struct bpf_ctx* ctx);
