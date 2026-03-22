// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "obs_bpf_metrics.h"
#include <assert.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>

#ifndef SHINKU_OBS_ENABLED
    #define SHINKU_OBS_ENABLED 1
#endif

#define OBS_CACHELINE_SIZE 64

static_assert(
    sizeof(atomic_uint_fast64_t) <= OBS_CACHELINE_SIZE,
    "atomic counter larger than cache line"
);

struct obs_aligned_counter {
    alignas(OBS_CACHELINE_SIZE) atomic_uint_fast64_t value;
    uint8_t pad[OBS_CACHELINE_SIZE - sizeof(atomic_uint_fast64_t)];
};

struct obs_metrics_config {
    uint8_t enabled;
    uint8_t bpf_enabled;
    uint32_t bpf_sample_mask;
};

enum obs_parser_reject_reason {
    OBS_REJECT_NOT_RESPONSE = 0,
    OBS_REJECT_BAD_QDCOUNT = 1,
    OBS_REJECT_TC = 2,
    OBS_REJECT_RCODE = 3,
    OBS_REJECT_NO_ANSWER = 4,
    OBS_REJECT_MALFORMED_NAME = 5,
    OBS_REJECT_MALFORMED_QUESTION = 6,
    OBS_REJECT_MALFORMED_RR = 7,
    OBS_REJECT_UNSUPPORTED_RTYPE = 8,
    OBS_REJECT_CNAME_NO_TERMINAL = 9,
    OBS_REJECT_BAD_ECS = 10,
    OBS_REJECT_BAD_TTL = 11,
    OBS_REJECT_MAX = 12,
};

struct obs_metrics {
    struct obs_metrics_config cfg;
    struct obs_aligned_counter parser_reject_total;
    struct obs_aligned_counter parser_reject_by_reason[OBS_REJECT_MAX];
    struct obs_aligned_counter cache_insert_total;
    struct obs_aligned_counter cache_insert_fail_total;
    struct obs_aligned_counter cleanup_removed_total;
    struct obs_aligned_counter rb_pkt_poll_error_total;
    struct obs_aligned_counter bpf_counters[OBS_BPF_METRIC_MAX];
};

struct obs_context {
    struct obs_metrics* metrics;
};

#define OBS_METRICS_FROM_CACHE_CTX(_cctx) (((_cctx) && (_cctx)->obs) ? (_cctx)->obs->metrics : NULL)

#if SHINKU_OBS_ENABLED
    #define OBS_COUNT_PARSER_REJECT_CTX(_cctx, _reason) \
        obs_metrics_count_parser_reject(OBS_METRICS_FROM_CACHE_CTX(_cctx), (_reason))
    #define OBS_COUNT_CACHE_INSERT_CTX(_cctx, _success) \
        obs_metrics_count_cache_insert(OBS_METRICS_FROM_CACHE_CTX(_cctx), (_success))
    #define OBS_ADD_CLEANUP_REMOVED_CTX(_cctx, _removed) \
        obs_metrics_add_cleanup_removed(OBS_METRICS_FROM_CACHE_CTX(_cctx), (_removed))
#else
    #define OBS_COUNT_PARSER_REJECT_CTX(_cctx, _reason) ((void)0)
    #define OBS_COUNT_CACHE_INSERT_CTX(_cctx, _success) ((void)0)
    #define OBS_ADD_CLEANUP_REMOVED_CTX(_cctx, _removed) ((void)0)
#endif

void obs_metrics_init(struct obs_metrics* metrics, const struct obs_metrics_config* cfg);
void obs_metrics_count_parser_reject(
    struct obs_metrics* metrics,
    enum obs_parser_reject_reason reason
);
void obs_metrics_count_cache_insert(struct obs_metrics* metrics, int success);
void obs_metrics_add_cleanup_removed(struct obs_metrics* metrics, uint64_t removed);
void obs_metrics_count_rb_poll_error(struct obs_metrics* metrics);
