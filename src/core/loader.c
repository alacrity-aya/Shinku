// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "loader.h"

#include "bpf_log.h"
#include "cache.skel.h"
#include "constants.h"
#include "dns_parser.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

// Error codes for setup_bpf
#define ERR_SKEL_LOAD -1
#define ERR_RB_CREATE -2
#define ERR_INVALID_IFACE -3
#define ERR_XDP_ATTACH -4
#define ERR_TC_ATTACH -5

static void sync_bpf_metrics(struct bpf_ctx* ctx) {
#if SHINKU_OBS_ENABLED
    if (!ctx || !ctx->metrics.cfg.enabled || !ctx->metrics.cfg.bpf_enabled)
        return;

    if (!ctx->skel || !ctx->obs_percpu_vals || ctx->obs_ncpu <= 0)
        return;

    int map_fd = bpf_map__fd(ctx->skel->maps.obs_bpf_metrics);
    if (map_fd < 0)
        return;

    for (uint32_t key = 0; key < OBS_BPF_METRIC_MAX; key++) {
        if (bpf_map_lookup_elem(map_fd, &key, ctx->obs_percpu_vals) != 0)
            continue;

        uint64_t total = 0;
        for (int cpu = 0; cpu < ctx->obs_ncpu; cpu++)
            total += ctx->obs_percpu_vals[cpu];

        atomic_store_explicit(&ctx->metrics.bpf_counters[key].value, total, memory_order_relaxed);
    }
#else
    (void)ctx;
#endif
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    char ts[LOG_TIMESTAMP_LEN];
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);

    const char* color_code = COL_RESET;
    const char* level_str = "INFO";

    switch (level) {
        case LIBBPF_WARN:
            color_code = COL_YELLOW;
            level_str = "WARN";
            break;
        case LIBBPF_INFO:
            color_code = COL_GREEN;
            level_str = "INFO";
            break;
        case LIBBPF_DEBUG:
            color_code = COL_GRAY;
            level_str = "DEBUG";
            return 0; // skip debug messages
        default:
            color_code = COL_RED;
            level_str = "ERROR";
            break;
    }

    fprintf(stderr, "%s[%s] [%s] ", color_code, ts, level_str);
    int ret = vfprintf(stderr, format, args);
    fprintf(stderr, "%s", COL_RESET);

    return ret;
}

static int attach_tc_legacy(struct bpf_ctx* ctx, int ifindex) {
    int err;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_EGRESS);

    DECLARE_LIBBPF_OPTS(
        bpf_tc_opts,
        opts,
        .prog_fd = bpf_program__fd(ctx->skel->progs.tc_tx),
        .priority = 1,
        .handle = 1,
    );

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook (clsact): %d\n", err);
        return err;
    }

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach legacy TC egress program: %d\n", err);
        return err;
    }

    ctx->tc_hook = hook;

    printf("Attached legacy TC (clsact/egress) on ifindex %d\n", ifindex);
    return 0;
}

int setup_bpf(struct bpf_ctx* ctx, const struct env* env) {
    int err;

#if SHINKU_OBS_ENABLED
    struct obs_metrics_config obs_cfg = {
        .enabled = env->obs_enabled ? 1 : 0,
        .bpf_enabled = (env->obs_enabled && env->obs_bpf_enabled) ? 1 : 0,
        .bpf_sample_mask = env->obs_bpf_sample_mask,
    };
#else
    struct obs_metrics_config obs_cfg = {
        .enabled = 0,
        .bpf_enabled = 0,
        .bpf_sample_mask = 0,
    };
#endif
    obs_metrics_init(&ctx->metrics, &obs_cfg);
    ctx->obs_ctx.metrics = &ctx->metrics;
    atomic_store_explicit(&ctx->bpf_ready, false, memory_order_relaxed);
    ctx->obs_ncpu = 0;
    ctx->obs_percpu_vals = NULL;

    libbpf_set_print(libbpf_print_fn);

    /* Open skeleton (don't load yet — need to configure arena size) */
    ctx->skel = cache_bpf__open();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return ERR_SKEL_LOAD;
    }

    /* Configure arena size from CLI --arena-pages before load */
    err = bpf_map__set_max_entries(ctx->skel->maps.arena, env->arena_pages);
    if (err) {
        fprintf(stderr, "Failed to set arena max_entries to %u: %d\n", env->arena_pages, err);
        goto cleanup;
    }

    ctx->skel->rodata->obs_bpf_enabled = obs_cfg.bpf_enabled;
    ctx->skel->rodata->obs_bpf_sample_mask = obs_cfg.bpf_sample_mask;

    bpf_program__set_autoattach(ctx->skel->progs.tc_tx, false);

    /* Load BPF programs and create maps */
    err = cache_bpf__load(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    if (ctx->metrics.cfg.bpf_enabled) {
        ctx->obs_ncpu = libbpf_num_possible_cpus();
        if (ctx->obs_ncpu <= 0) {
            fprintf(stderr, "Failed to get possible CPU count for observability metrics\n");
            err = ERR_SKEL_LOAD;
            goto cleanup;
        }

        ctx->obs_percpu_vals = calloc((size_t)ctx->obs_ncpu, sizeof(uint64_t));
        if (!ctx->obs_percpu_vals) {
            fprintf(stderr, "Failed to allocate percpu buffer for observability metrics\n");
            err = ERR_SKEL_LOAD;
            goto cleanup;
        }
    }

    /* Wire up cache context — skeleton auto-mmap's arena via __arena globals */
    ctx->cache_ctx.entries = ctx->skel->arena->cache_entries;
    ctx->cache_ctx.next_idx = &ctx->skel->arena->next_entry_idx;
    ctx->cache_ctx.max_entries = CACHE_MAP_MAX_ENTRIES;
    ctx->cache_ctx.cache_map_fd = bpf_map__fd(ctx->skel->maps.cache_map);
    ctx->cache_ctx.next_gen = 0;
    ctx->cache_ctx.obs = &ctx->obs_ctx;
    ctx->cache_ctx.slot_owners =
        calloc(CACHE_MAP_MAX_ENTRIES, sizeof(struct cache_key));
    if (!ctx->cache_ctx.slot_owners) {
        fprintf(stderr, "Failed to allocate slot_owners array\n");
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    err = cache_bpf__attach(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

#if SHINKU_BPF_LOG_ENABLED
    // rb_log
    ctx->log_opt.min_level = env->log_level;
    ctx->log_opt.show_timestamp = true;
    ctx->log_opt.use_color = true;

    ctx->rb_log =
        ring_buffer__new(bpf_map__fd(ctx->skel->maps._rb_log), print_bpf_log, &ctx->log_opt, NULL);
    if (!ctx->rb_log) {
        fprintf(stderr, "Failed to create ring buffer: rb_log\n");
        err = ERR_RB_CREATE;
        goto cleanup;
    }
#else
    (void)env->log_level; /* unused when logging disabled */
#endif

    // xdp
    uint32_t ifindex = if_nametoindex(env->interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name: %s\n", env->interface);
        err = ERR_INVALID_IFACE;
        goto cleanup;
    }

    ctx->skel->links.xdp_rx = bpf_program__attach_xdp(ctx->skel->progs.xdp_rx, ifindex);
    err = libbpf_get_error(ctx->skel->links.xdp_rx);
    if (err) {
        fprintf(stderr, "Failed to attach XDP(Ingress) to %s (Error: %d)\n", env->interface, err);
        ctx->skel->links.xdp_rx = NULL;
        err = ERR_XDP_ATTACH;
        goto cleanup;
    }

    // tc
    // TODO: why tcx failed? I have no idea about that
    ctx->skel->links.tc_tx = bpf_program__attach_tcx(ctx->skel->progs.tc_tx, ifindex, NULL);
    err = libbpf_get_error(ctx->skel->links.tc_tx);
    if (err) {
        fprintf(stderr, "Failed to attach TCX(Egress) to %s (Error: %d)\n", env->interface, err);
        if (err == -EOPNOTSUPP || err == -EINVAL) {
            fprintf(stderr, "TCX not supported on %s, falling back to TC\n", env->interface);
            ctx->skel->links.tc_tx = NULL;

            err = attach_tc_legacy(ctx, ifindex);
            if (err) {
                err = ERR_TC_ATTACH;
                goto cleanup;
            }
        } else {
            ctx->skel->links.tc_tx = NULL;
            err = ERR_TC_ATTACH;
            goto cleanup;
        }
    }

    // rb_pkt — pass cache_ctx so handle_packet() can write to arena + cache_map
    ctx->rb_pkt =
        ring_buffer__new(bpf_map__fd(ctx->skel->maps.rb_pkt), handle_packet, &ctx->cache_ctx, NULL);
    if (!ctx->rb_pkt) {
        fprintf(stderr, "Failed to create ring buffer: rb_pkt\n");
        err = ERR_RB_CREATE;
        goto cleanup;
    }

    if (ctx->metrics.cfg.enabled) {
        err = obs_http_start(&ctx->obs_http, env->metrics_port, &ctx->metrics, &ctx->bpf_ready);
        if (err)
            fprintf(stderr, "Failed to start observability HTTP server on 127.0.0.1:%u\n", env->metrics_port);
    }

    atomic_store_explicit(&ctx->bpf_ready, true, memory_order_release);

    printf("Successfully attached to interface: %s (ifindex: %d)\n", env->interface, ifindex);

    return 0;

cleanup:
    cleanup_bpf(ctx);
    return err;
}

int poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms) {
    int ret = ring_buffer__poll(ctx->rb_pkt, timeout_ms);
    if (ret < 0)
        obs_metrics_count_rb_poll_error(&ctx->metrics);

    sync_bpf_metrics(ctx);
    return ret;
}

int dump_bpf_log([[maybe_unused]] struct bpf_ctx* ctx, [[maybe_unused]] int timeout_ms) {
#if SHINKU_BPF_LOG_ENABLED
    return ring_buffer__poll(ctx->rb_log, timeout_ms);
#else
    return 0;
#endif
}

void cleanup_bpf(struct bpf_ctx* ctx) {
    atomic_store_explicit(&ctx->bpf_ready, false, memory_order_release);
    obs_http_stop(&ctx->obs_http);
    stop_cleanup_thread(ctx);

    if (ctx->rb_log) {
        ring_buffer__free(ctx->rb_log);
        ctx->rb_log = NULL;
    }

    if (ctx->rb_pkt) {
        ring_buffer__free(ctx->rb_pkt);
        ctx->rb_pkt = NULL;
    }

    /* detach legacy TC */
    if (ctx->tc_hook.ifindex) {
        bpf_tc_hook_destroy(&ctx->tc_hook);
        memset(&ctx->tc_hook, 0, sizeof(ctx->tc_hook));
    }

    free(ctx->cache_ctx.slot_owners);
    ctx->cache_ctx.slot_owners = NULL;

    free(ctx->obs_percpu_vals);
    ctx->obs_percpu_vals = NULL;
    ctx->obs_ncpu = 0;

    if (ctx->skel) {
        cache_bpf__destroy(ctx->skel);
        ctx->skel = NULL;
    }
}

/* ============================================================================
 * Cleanup Thread
 * ============================================================================ */

static void* cleanup_thread_func(void* arg) {
    struct bpf_ctx* ctx = arg;
    struct timespec sleep_time = {
        .tv_sec = ctx->cleanup_cfg.interval_secs,
        .tv_nsec = 0,
    };

    while (atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire)) {
        nanosleep(&sleep_time, NULL);
        if (!atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire))
            break;

        int removed = cleanup_expired_entries(&ctx->cache_ctx);
        (void)removed; /* Log already printed inside cleanup function */
    }

    return NULL;
}

int start_cleanup_thread(struct bpf_ctx* ctx, uint32_t interval_secs) {
    if (interval_secs == 0)
        interval_secs = 10; /* Default: 10 seconds */

    ctx->cleanup_cfg.interval_secs = interval_secs;
    atomic_store_explicit(&ctx->cleanup_running, true, memory_order_release);

    int err = pthread_create(&ctx->cleanup_thread, NULL, cleanup_thread_func, ctx);
    if (err != 0) {
        fprintf(stderr, "Failed to create cleanup thread: %d\n", err);
        atomic_store_explicit(&ctx->cleanup_running, false, memory_order_release);
        return -err;
    }

    printf("Started cleanup thread (interval: %us)\n", interval_secs);
    return 0;
}

void stop_cleanup_thread(struct bpf_ctx* ctx) {
    if (!atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire))
        return;

    atomic_store_explicit(&ctx->cleanup_running, false, memory_order_release);

    /* Wake up the thread by sending a signal or waiting for it to finish */
    pthread_join(ctx->cleanup_thread, NULL);
    printf("Cleanup thread stopped\n");
}
