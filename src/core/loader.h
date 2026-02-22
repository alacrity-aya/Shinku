#pragma once

#include "bpf_log.h"

#include "cli/config.h"
#include <bpf/libbpf.h>
#include <errno.h>

struct cache_bpf;

struct bpf_ctx {
    struct cache_bpf* skel;
    struct ring_buffer* rb_log;
    struct ring_buffer* rb_pkt;
    struct log_options log_opt;

    struct bpf_tc_hook tc_hook;
};

int setup_bpf(struct bpf_ctx* ctx, const struct env* env);
int dump_bpf_log(struct bpf_ctx* ctx, int timeout_ms);
void cleanup_bpf(struct bpf_ctx* ctx);
int poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms);
