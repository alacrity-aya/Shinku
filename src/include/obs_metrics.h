// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "obs_bpf_metrics.h"
#include "runtime/events.h"
#include <assert.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>

/**
 * @file obs_metrics.h
 * @brief Observability metrics system for DNS cache.
 *
 * This header defines the metrics collection infrastructure for monitoring
 * DNS cache performance, error rates, and system health. All counters use
 * cache-line aligned atomic operations for thread-safe, lock-free updates.
 *
 * @note Compile-time toggle: Set SHINKU_OBS_ENABLED=0 to disable all metrics.
 */

#ifndef SHINKU_OBS_ENABLED
    #define SHINKU_OBS_ENABLED 1
#endif

/** @brief Cache line size for alignment (x86_64) */
#define OBS_CACHELINE_SIZE 64

static_assert(
    sizeof(atomic_uint_fast64_t) <= OBS_CACHELINE_SIZE,
    "atomic counter larger than cache line"
);

/**
 * @struct obs_aligned_counter
 * @brief Cache-line aligned atomic counter to prevent false sharing.
 *
 * Each counter occupies a full cache line to ensure that concurrent updates
 * to different counters do not cause cache line bouncing between cores.
 */
struct obs_aligned_counter {
    alignas(OBS_CACHELINE_SIZE) atomic_uint_fast64_t value; /**< Atomic counter value */
    uint8_t pad[OBS_CACHELINE_SIZE - sizeof(atomic_uint_fast64_t)]; /**< Padding */
};

/**
 * @struct obs_metrics_config
 * @brief Configuration for metrics collection.
 */
struct obs_metrics_config {
    uint8_t enabled; /**< Master enable switch */
    uint8_t bpf_enabled; /**< Enable BPF-side metric collection */
    uint32_t bpf_sample_mask; /**< Sampling mask for BPF metrics (1=sample every packet) */
};

/**
 * @enum obs_parser_reject_reason
 * @brief Reasons for rejecting DNS responses during parsing.
 */
enum obs_parser_reject_reason {
    OBS_REJECT_NOT_RESPONSE = 0, /**< Packet is not a DNS response (QR=0) */
    OBS_REJECT_BAD_QDCOUNT = 1, /**< Invalid question count (QDCOUNT != 1) */
    OBS_REJECT_TC = 2, /**< Truncated response (TC=1) */
    OBS_REJECT_RCODE = 3, /**< Non-zero RCODE (error response) */
    OBS_REJECT_NO_ANSWER = 4, /**< No answer records (ANCOUNT=0) */
    OBS_REJECT_MALFORMED_NAME = 5, /**< Malformed DNS name in packet */
    OBS_REJECT_MALFORMED_QUESTION = 6, /**< Malformed question section */
    OBS_REJECT_MALFORMED_RR = 7, /**< Malformed resource record */
    OBS_REJECT_UNSUPPORTED_RTYPE = 8, /**< Unsupported record type */
    OBS_REJECT_IPV6_IGNORED = 9, /**< IPv6 query/record ignored by policy */
    OBS_REJECT_CNAME_NO_TERMINAL_A = 10, /**< CNAME chain for A query without terminal A */
    OBS_REJECT_CNAME_IPV6_ONLY_TERMINAL =
        11, /**< CNAME chain ends only in AAAA under IPv6-ignore policy */
    OBS_REJECT_BAD_ECS = 12, /**< Invalid EDNS Client Subnet option */
    OBS_REJECT_BAD_TTL = 13, /**< Invalid TTL value */
    OBS_REJECT_NEGATIVE_NO_SOA = 14, /**< Negative response without SOA */
    OBS_REJECT_NEGATIVE_BAD_POLICY = 15, /**< Negative response with invalid TTL */
    OBS_REJECT_MAX = 16, /**< Sentinel: number of reject reasons */
};

/**
 * @enum obs_negative_type
 * @brief Types of negative cache entries.
 */
enum obs_negative_type {
    OBS_NEGATIVE_NXDOMAIN = 0, /**< Domain does not exist (RCODE=3) */
    OBS_NEGATIVE_NODATA = 1, /**< Domain exists but no requested type (ANCOUNT=0) */
    OBS_NEGATIVE_MAX = 2, /**< Sentinel: number of negative types */
};

/**
 * @enum obs_degraded_reason
 * @brief Reasons for degraded mode activation.
 */
enum obs_degraded_reason {
    OBS_DEGRADED_STARTUP_ATTACH_RETRY = 0, /**< XDP/TC attach required retries */
    OBS_DEGRADED_STARTUP_ATTACH_FAILED = 1, /**< XDP/TC attach failed after retries */
    OBS_DEGRADED_TCX_ATTACH_FAILED = 2, /**< TCX attach failed, fell back to TC */
    OBS_DEGRADED_CLEANUP_THREAD_DOWN = 3, /**< Cleanup thread stopped */
    OBS_DEGRADED_PKT_POLL_ERRORS = 4, /**< Ring buffer poll errors */
    OBS_DEGRADED_RING_BACKLOG = 5, /**< Ring buffer backlog (userspace lag) */
    OBS_DEGRADED_OBS_HTTP_DOWN = 6, /**< Observability HTTP server down */
    OBS_DEGRADED_BPF_METRICS_SYNC_FAIL = 7, /**< BPF metrics sync failed */
    OBS_DEGRADED_CACHE_MAP_UPDATE_FAIL = 8, /**< Cache map update failures */
    OBS_DEGRADED_MAX = 9, /**< Sentinel: number of degraded reasons */
};

/**
 * @struct obs_metrics
 * @brief Complete metrics state for the DNS cache system.
 *
 * All counters are cache-line aligned for optimal concurrent access.
 */
struct obs_metrics {
    struct obs_metrics_config cfg; /**< Configuration */
    struct obs_aligned_counter parser_reject_total; /**< Total parser rejections */
    struct obs_aligned_counter parser_reject_by_reason[OBS_REJECT_MAX]; /**< Rejections by reason */
    struct obs_aligned_counter cache_insert_total; /**< Total cache insert attempts */
    struct obs_aligned_counter cache_insert_fail_total; /**< Failed cache inserts */
    struct obs_aligned_counter cache_admission_attempt_total;
    struct obs_aligned_counter cache_admission_accept_total;
    struct obs_aligned_counter cache_admission_reject_total;
    struct obs_aligned_counter cache_admission_reject_recent_total;
    struct obs_aligned_counter cache_admission_reject_ttl_total;
    struct obs_aligned_counter cache_admission_reject_freq_total;
    struct obs_aligned_counter cache_eviction_total;
    struct obs_aligned_counter cache_eviction_hot_total;
    struct obs_aligned_counter cache_eviction_cold_total;
    struct obs_aligned_counter cache_hot_segment_size;
    struct obs_aligned_counter cache_cold_segment_size;
    struct obs_aligned_counter
        negative_cache_accept_total[OBS_NEGATIVE_MAX]; /**< Negative cache accepts */
    struct obs_aligned_counter
        negative_cache_reject_total[OBS_NEGATIVE_MAX]; /**< Negative cache rejects */
    struct obs_aligned_counter cleanup_removed_total; /**< Expired entries removed */
    struct obs_aligned_counter rb_pkt_poll_error_total; /**< Ring buffer poll errors */
    struct obs_aligned_counter degraded_mode; /**< Current degraded mode state (0/1) */
    struct obs_aligned_counter degraded_transition_total; /**< Total degraded mode transitions */
    struct obs_aligned_counter
        degraded_reason_total[OBS_DEGRADED_MAX]; /**< Reason activation counts */
    struct obs_aligned_counter bpf_counters[OBS_BPF_METRIC_MAX]; /**< BPF-side counters */
    struct obs_aligned_counter metrics_truncated_total;
};

/**
 * @struct obs_context
 * @brief Observability context for cache operations.
 */
struct obs_context {
    struct obs_metrics* metrics;
};

/* ============================================================================
 * Metrics Functions
 * ============================================================================ */

/**
 * @brief Initialize metrics structure with configuration.
 * @param metrics Pointer to metrics structure to initialize.
 * @param cfg Configuration for metrics collection.
 * @note All counters are initialized to zero.
 */
void obs_metrics_init(struct obs_metrics* metrics, const struct obs_metrics_config* cfg);

/**
 * @brief Count a parser rejection event.
 * @param metrics Metrics structure (may be NULL).
 * @param reason Reason for rejection.
 * @note Increments both parser_reject_total and parser_reject_by_reason[reason].
 */
void obs_metrics_count_parser_reject(
    struct obs_metrics* metrics,
    enum obs_parser_reject_reason reason
);

/**
 * @brief Count a cache insert attempt.
 * @param metrics Metrics structure (may be NULL).
 * @param success Non-zero if insert succeeded, zero if failed.
 */
void obs_metrics_count_cache_insert(struct obs_metrics* metrics, int success);

void obs_metrics_count_cache_admission_attempt(struct obs_metrics* metrics);
void obs_metrics_count_cache_admission_accept(struct obs_metrics* metrics);
void obs_metrics_count_cache_admission_reject(struct obs_metrics* metrics);
void obs_metrics_count_cache_admission_reject_recent(struct obs_metrics* metrics);
void obs_metrics_count_cache_admission_reject_ttl(struct obs_metrics* metrics);
void obs_metrics_count_cache_admission_reject_freq(struct obs_metrics* metrics);
void obs_metrics_count_cache_eviction(struct obs_metrics* metrics, int was_hot);
void obs_metrics_set_cache_segment_sizes(struct obs_metrics* metrics, uint32_t hot, uint32_t cold);

/**
 * @brief Count an accepted negative cache entry.
 * @param metrics Metrics structure (may be NULL).
 * @param type Type of negative cache entry (NXDOMAIN or NODATA).
 */
void obs_metrics_count_negative_accept(struct obs_metrics* metrics, enum obs_negative_type type);

/**
 * @brief Count a rejected negative cache entry.
 * @param metrics Metrics structure (may be NULL).
 * @param type Type of negative cache entry (NXDOMAIN or NODATA).
 */
void obs_metrics_count_negative_reject(struct obs_metrics* metrics, enum obs_negative_type type);

/**
 * @brief Add to the cleanup removed counter.
 * @param metrics Metrics structure (may be NULL).
 * @param removed Number of entries removed in this cleanup cycle.
 */
void obs_metrics_add_cleanup_removed(struct obs_metrics* metrics, uint64_t removed);

/**
 * @brief Count a ring buffer poll error.
 * @param metrics Metrics structure (may be NULL).
 */
void obs_metrics_count_rb_poll_error(struct obs_metrics* metrics);

/**
 * @brief Record a degraded mode reason.
 * @param metrics Metrics structure (may be NULL).
 * @param reason Reason for degraded mode.
 * @note Increments degraded_reason_total[reason]. Does NOT set degraded_mode gauge.
 */
void obs_metrics_mark_degraded(struct obs_metrics* metrics, enum obs_degraded_reason reason);

void obs_metrics_handle_degraded_event(
    enum shinku_event_type type,
    const void* payload,
    void* user_ctx
);

void obs_metrics_count_metrics_truncated(struct obs_metrics* metrics);
