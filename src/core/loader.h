// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include "dns_parser.h"
#include "obs_http.h"
#include "obs_metrics.h"

#include "cli/config.h"
#include <bpf/libbpf.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

struct cache_bpf;

/* Cleanup thread configuration */
struct cleanup_config {
    uint32_t interval_secs;    /* Cleanup interval in seconds */
};

struct bpf_ctx {
    struct cache_bpf* skel;
    struct ring_buffer* rb_log;
    struct ring_buffer* rb_pkt;
    struct log_options log_opt;

    struct bpf_tc_hook tc_hook;

    /* Cache context for ring buffer callback */
    struct cache_ctx cache_ctx;

    struct obs_metrics metrics;
    struct obs_context obs_ctx;
    struct obs_http_server obs_http;
    atomic_bool bpf_ready;
    int obs_ncpu;
    uint64_t* obs_percpu_vals;

    /* Cleanup thread */
    pthread_t cleanup_thread;
    struct cleanup_config cleanup_cfg;
    atomic_bool cleanup_running;
};

int setup_bpf(struct bpf_ctx* ctx, const struct env* env);
int dump_bpf_log(struct bpf_ctx* ctx, int timeout_ms);
void cleanup_bpf(struct bpf_ctx* ctx);
int poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms);

/* Cleanup thread management */
int start_cleanup_thread(struct bpf_ctx* ctx, uint32_t interval_secs);
void stop_cleanup_thread(struct bpf_ctx* ctx);
