// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "degraded_mode.h"
#include "obs_metrics.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct obs_http_server {
    pthread_t thread;
    atomic_bool running;
    int listen_fd;
    uint16_t port;
    struct obs_metrics* metrics;
    struct degraded_state* degraded;
    atomic_bool* bpf_ready;
};

int obs_http_start(
    struct obs_http_server* srv,
    uint16_t port,
    struct obs_metrics* metrics,
    struct degraded_state* degraded,
    atomic_bool* bpf_ready
);
void obs_http_stop(struct obs_http_server* srv);
