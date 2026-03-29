// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "degraded_mode.h"
#include "obs_metrics.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @file obs_http.h
 * @brief HTTP server for observability metrics export.
 *
 * This module provides a lightweight HTTP server that exposes
 * Prometheus-compatible metrics at /metrics endpoint. It runs in
 * a dedicated thread and serves metrics for monitoring systems.
 */

/**
 * @struct obs_http_server
 * @brief HTTP server state for observability metrics.
 */
struct obs_http_server {
    pthread_t thread; /**< Server thread handle */
    atomic_bool running; /**< Server running flag */
    atomic_int listen_fd; /**< Listening socket file descriptor */
    uint16_t port; /**< Listening port */
    struct obs_metrics* metrics; /**< Pointer to metrics to export */
    struct degraded_state* degraded; /**< Pointer to degraded state */
    atomic_bool* bpf_ready; /**< Pointer to BPF ready flag */
};

/**
 * @brief Start the observability HTTP server.
 * @param srv Server structure to initialize.
 * @param port Port to listen on (0 for dynamic allocation).
 * @param metrics Pointer to metrics structure to export.
 * @param degraded Pointer to degraded state for health reporting.
 * @param bpf_ready Pointer to BPF ready flag for readiness checks.
 * @return 0 on success, negative on error.
 *
 * Spawns a background thread that listens for HTTP connections.
 * Endpoints:
 *   - GET /metrics : Prometheus metrics export
 *   - GET /healthz : Health check (always 200 OK)
 *   - GET /readyz  : Readiness check (503 until BPF ready, then 200)
 *
 * @note If port is 0, the OS assigns a dynamic port available via srv->port.
 */
int obs_http_start(
    struct obs_http_server* srv,
    uint16_t port,
    struct obs_metrics* metrics,
    struct degraded_state* degraded,
    atomic_bool* bpf_ready
);

/**
 * @brief Stop the observability HTTP server.
 * @param srv Server structure.
 *
 * Signals the server thread to stop, closes the listening socket,
 * and waits for the thread to exit.
 */
void obs_http_stop(struct obs_http_server* srv);
