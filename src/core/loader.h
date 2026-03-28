// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include "degraded_mode.h"
#include "dns_parser.h"
#include "obs_http.h"
#include "obs_metrics.h"
#include "runtime/events.h"

#include "cli/config.h"
#include <bpf/libbpf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

/**
 * @file loader.h
 * @brief BPF program loader and lifecycle management.
 *
 * This module handles loading, attaching, and managing BPF programs
 * for DNS caching. It also manages the cleanup thread and observability
 * HTTP server.
 */

struct cache_bpf;

/**
 * @struct cleanup_config
 * @brief Configuration for the cache cleanup thread.
 */
struct cleanup_config {
    uint32_t interval_secs; /**< Cleanup interval in seconds */
};

/**
 * @struct bpf_ctx
 * @brief Complete BPF application context.
 *
 * This structure holds all state for the DNS cache BPF application,
 * including skeleton, ring buffers, cache context, metrics, and
 * thread management.
 */
struct bpf_ctx {
    struct cache_bpf* skel; /**< BPF skeleton for program management */
    struct ring_buffer* rb_log; /**< Ring buffer for BPF logs */
    struct ring_buffer* rb_pkt; /**< Ring buffer for DNS packets */
    struct log_options log_opt; /**< Log output configuration */
    struct bpf_tc_hook tc_hook; /**< TC hook for egress capture */

    struct cache_context cache_context; /**< Cache management context */
    struct dns_parser_runtime parser_runtime;
    struct dns_parser_context parser_context;

    struct obs_metrics metrics; /**< Observability metrics */
    struct obs_context obs_ctx; /**< Observability context */
    struct degraded_state degraded; /**< Degraded mode state machine */
    struct shinku_event_bus events; /**< Internal event bus for component decoupling */
    struct obs_http_server obs_http; /**< HTTP server for metrics */
    atomic_bool bpf_ready; /**< BPF programs ready flag */

    int obs_ncpu; /**< Number of CPUs for per-CPU metrics */
    uint64_t* obs_percpu_vals; /**< Buffer for per-CPU metric reads */
    uint32_t pkt_poll_err_streak; /**< Consecutive poll errors */
    uint32_t rb_backlog_streak; /**< Consecutive high-load polls */

    /* Cleanup thread */
    pthread_t cleanup_thread; /**< Cleanup thread handle */
    struct cleanup_config cleanup_cfg; /**< Cleanup configuration */
    atomic_bool cleanup_running; /**< Cleanup thread running flag */
    pthread_mutex_t cleanup_wait_lock;
    pthread_cond_t cleanup_wait_cond;
    bool cleanup_wait_sync_initialized;
    pthread_mutex_t cache_lock;
};

/**
 * @brief Setup and attach BPF programs.
 * @param ctx BPF context to initialize.
 * @param env Configuration environment from CLI.
 * @return 0 on success, negative on error.
 *
 * Performs:
 *   - Opens BPF skeleton
 *   - Sets up arena memory options
 *   - Loads and attaches XDP/TC programs
 *   - Initializes ring buffers
 *   - Starts observability HTTP server
 *
 * @note Uses bounded retry with exponential backoff for XDP/TC attach.
 */
int loader_setup_bpf(struct bpf_ctx* ctx, const struct env* env);

/**
 * @brief Poll for BPF log events.
 * @param ctx BPF context.
 * @param timeout_ms Timeout in milliseconds (-1 for infinite).
 * @return Number of events processed, or negative on error.
 *
 * Processes log events from the BPF ring buffer and prints them.
 */
int loader_dump_bpf_log(struct bpf_ctx* ctx, int timeout_ms);

/**
 * @brief Cleanup and tear down BPF programs.
 * @param ctx BPF context to cleanup.
 *
 * Stops cleanup thread, destroys ring buffers, detaches programs,
 * and frees all resources.
 */
void loader_cleanup_bpf(struct bpf_ctx* ctx);

/**
 * @brief Poll for DNS packet events from BPF.
 * @param ctx BPF context.
 * @param timeout_ms Timeout in milliseconds (-1 for infinite).
 * @return Number of events processed, or negative on error.
 *
 * Polls the packet ring buffer and processes DNS responses through
 * cache_handle_event(). Tracks poll errors and backlog for degraded mode.
 */
int loader_poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms);

/* ============================================================================
 * Cleanup Thread Management
 * ============================================================================ */

/**
 * @brief Start the cache cleanup thread.
 * @param ctx BPF context.
 * @param interval_secs Cleanup interval in seconds.
 * @return 0 on success, negative on error.
 *
 * Spawns a background thread that periodically calls
 * cache_cleanup_expired_entries() to remove stale cache entries.
 */
int loader_start_cleanup_thread(struct bpf_ctx* ctx, uint32_t interval_secs);

/**
 * @brief Stop the cache cleanup thread.
 * @param ctx BPF context.
 *
 * Signals the cleanup thread to stop and waits for it to exit.
 */
void loader_stop_cleanup_thread(struct bpf_ctx* ctx);
