// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include "cache_types.h"
#include "parser_runtime.h"

#include <bpf/libbpf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file loader.h
 * @brief BPF program loader and lifecycle management.
 *
 * This module handles loading, attaching, and managing BPF programs
 * for DNS caching. It also manages the cleanup thread.
 */

struct cache_bpf;

struct env {
    const char* interface;
    enum log_level log_level;
    uint32_t arena_pages;
    uint32_t cleanup_interval_ms;
    uint32_t admission_enabled;
    uint32_t pressure_mode;
    uint32_t admission_min_ttl;
    uint32_t admission_dampen_window_ms;
    uint32_t hot_threshold;
    uint32_t freq_width;
    uint32_t freq_epoch_ops;
};

/**
 * @struct cleanup_config
 * @brief Configuration for the cache cleanup thread.
 */
struct cleanup_config {
    uint32_t interval_ms; /**< Cleanup interval in milliseconds */
};

/**
 * @struct bpf_ctx
 * @brief Complete BPF application context.
 *
 * This structure holds all state for the DNS cache BPF application,
 * including skeleton, ring buffers, cache context, and thread management.
 */
struct bpf_ctx {
    struct cache_bpf* skel;     /**< BPF skeleton for program management */
    struct ring_buffer* rb_log; /**< Ring buffer for BPF logs */
    struct ring_buffer* rb_pkt; /**< Ring buffer for DNS packets */
    struct log_options log_opt; /**< Log output configuration */
    struct bpf_tc_hook tc_hook; /**< TC hook for egress capture */

    struct cache_context cache_context; /**< Cache management context */
    struct dns_parser_runtime parser_runtime;
    struct dns_parser_context parser_context;

    /* Cleanup thread */
    pthread_t cleanup_thread;          /**< Cleanup thread handle */
    struct cleanup_config cleanup_cfg; /**< Cleanup configuration */
    atomic_bool cleanup_running;       /**< Cleanup thread running flag */
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
 * cache_handle_event().
 */
int loader_poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms);

/* ============================================================================
 * Cleanup Thread Management
 * ============================================================================ */

/**
 * @brief Start the cache cleanup thread.
 * @param ctx BPF context.
 * @param interval_ms Cleanup interval in milliseconds.
 * @return 0 on success, negative on error.
 *
 * Spawns a background thread that periodically calls
 * cache_cleanup_expired_entries() to remove stale cache entries.
 */
int loader_start_cleanup_thread(struct bpf_ctx* ctx, uint32_t interval_ms);

/**
 * @brief Stop the cache cleanup thread.
 * @param ctx BPF context.
 *
 * Signals the cleanup thread to stop and waits for it to exit.
 */
void loader_stop_cleanup_thread(struct bpf_ctx* ctx);

#ifdef __cplusplus
}
#endif
