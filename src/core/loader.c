// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

/**
 * @file loader.c
 * @brief BPF program loader and lifecycle management implementation.
 *
 * This file implements the core BPF infrastructure:
 *   - Loading and attaching XDP/TC programs with retry logic
 *   - Ring buffer initialization and polling
 *   - Cleanup thread management
 */
#include "loader.h"

#include "bpf_log.h"
#include "cache.skel.h"
#include "constants.h"
#include "dns_parser.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static uint32_t floor_power_of_two(uint32_t value) {
    if (value == 0)
        return 0;

    uint32_t p = 1;
    while ((p << 1) != 0 && (p << 1) <= value)
        p <<= 1;
    return p;
}

/** @defgroup loader_errors Internal error codes for loader_setup_bpf */
#define ERR_SKEL_LOAD -1     /**< Skeleton load failed */
#define ERR_RB_CREATE -2     /**< Ring buffer creation failed */
#define ERR_INVALID_IFACE -3 /**< Invalid network interface */
#define ERR_XDP_ATTACH -4    /**< XDP attach failed */
#define ERR_TC_ATTACH -5     /**< TC attach failed */

#define ATTACH_RETRY_MAX 5      /**< Maximum attachment retry attempts */
#define ATTACH_RETRY_BASE_MS 50 /**< Base retry delay (ms) */
#define ATTACH_RETRY_MAX_MS 800 /**< Maximum retry delay (ms) */

/**
 * @brief Check if error indicates TCX is not supported.
 * @param err Error code from TCX attach attempt.
 * @return Non-zero if TCX is unsupported, zero otherwise.
 */
static int is_tcx_not_supported_err(int err) {
    return err == -EOPNOTSUPP || err == -EINVAL || err == -ENOTSUP || err == -ENOSYS;
}

/**
 * @brief libbpf print callback for logging library messages.
 * @param level Log level (WARN, INFO, DEBUG).
 * @param format Printf-style format string.
 * @param args Format arguments.
 * @return Number of characters printed.
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    char ts[LOG_TIMESTAMP_LEN];
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_r(&t, &tm_info);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm_info);

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

/**
 * @brief Attach TC program using legacy TC-BPF API.
 * @param ctx BPF context containing skeleton.
 * @param ifindex Network interface index.
 * @return 0 on success, negative on error.
 * @note Used as fallback when TCX (tcx_link_create) is not supported.
 */
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

int loader_setup_bpf(struct bpf_ctx* ctx, const struct env* env) {
    int err;

    err = pthread_mutex_init(&ctx->cache_lock, NULL);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize cache lock: %d\n", err);
        return -err;
    }
    ctx->cache_context.slot_owners_lock = &ctx->cache_lock;

    err = pthread_mutex_init(&ctx->cleanup_wait_lock, NULL);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize cleanup wait lock: %d\n", err);
        pthread_mutex_destroy(&ctx->cache_lock);
        ctx->cache_context.slot_owners_lock = NULL;
        return -err;
    }

    err = pthread_cond_init(&ctx->cleanup_wait_cond, NULL);
    if (err != 0) {
        fprintf(stderr, "Failed to initialize cleanup wait condition: %d\n", err);
        pthread_mutex_destroy(&ctx->cleanup_wait_lock);
        pthread_mutex_destroy(&ctx->cache_lock);
        ctx->cache_context.slot_owners_lock = NULL;
        return -err;
    }
    ctx->cleanup_wait_sync_initialized = true;

    if (!env || env->arena_pages < ARENA_DEFAULT_PAGES) {
        fprintf(
            stderr,
            "Invalid arena-pages: %u (minimum required: %u)\n",
            env ? env->arena_pages : 0,
            ARENA_DEFAULT_PAGES
        );
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    libbpf_set_print(libbpf_print_fn);

    /* Open skeleton (don't load yet — need to configure arena size) */
    ctx->skel = cache_bpf__open();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    /* Configure arena size from CLI --arena-pages before load */
    err = bpf_map__set_max_entries(ctx->skel->maps.arena, env->arena_pages);
    if (err) {
        fprintf(stderr, "Failed to set arena max_entries to %u: %d\n", env->arena_pages, err);
        goto cleanup;
    }

    bpf_program__set_autoattach(ctx->skel->progs.tc_tx, false);

    /* Load BPF programs and create maps */
    err = cache_bpf__load(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    /* Wire up cache context — skeleton auto-mmap's arena via __arena globals */
    ctx->cache_context.entries = ctx->skel->arena->cache_entries;
    ctx->cache_context.next_idx = &ctx->skel->arena->next_entry_idx;
    ctx->cache_context.max_entries = CACHE_MAP_MAX_ENTRIES;
    ctx->cache_context.cache_map_fd = bpf_map__fd(ctx->skel->maps.cache_map);
    ctx->cache_context.next_gen = 0;
    ctx->cache_context.admission.enabled = env->admission_enabled ? 1 : 0;
    ctx->cache_context.admission.pressure_mode = env->pressure_mode ? 1 : 0;
    ctx->cache_context.admission.min_ttl = env->admission_min_ttl;
    ctx->cache_context.admission.dampen_window_ns = ((uint64_t)env->admission_dampen_window_ms) * 1000000ULL;
    ctx->cache_context.segments.hot_threshold = env->hot_threshold;
    ctx->cache_context.sketch.width = env->freq_width;
    ctx->cache_context.sketch.epoch_ops = env->freq_epoch_ops;
    ctx->cache_context.sketch.ops = 0;
    uint32_t normalized_freq_width = floor_power_of_two(ctx->cache_context.sketch.width);
    if (normalized_freq_width == 0)
        normalized_freq_width = 1;
    if (normalized_freq_width != ctx->cache_context.sketch.width) {
        fprintf(
            stderr,
            "[Config] freq_width=%u adjusted to power-of-two=%u for sketch indexing\n",
            ctx->cache_context.sketch.width,
            normalized_freq_width
        );
        ctx->cache_context.sketch.width = normalized_freq_width;
    }
    ctx->parser_context.cache = &ctx->cache_context;
    ctx->parser_context.runtime = &ctx->parser_runtime;
    ctx->cache_context.slot_owners = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(struct cache_key));
    if (!ctx->cache_context.slot_owners) {
        fprintf(stderr, "Failed to allocate slot_owners array\n");
    }

    ctx->cache_context.recent.capacity = CACHE_MAP_MAX_ENTRIES;
    ctx->cache_context.recent.keys = calloc(ctx->cache_context.recent.capacity, sizeof(struct cache_key));
    ctx->cache_context.recent.ns_timestamps = calloc(ctx->cache_context.recent.capacity, sizeof(uint64_t));
    ctx->cache_context.segments.slot_hit_count = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(uint32_t));
    ctx->cache_context.segments.slot_hot = calloc(CACHE_MAP_MAX_ENTRIES, sizeof(uint8_t));

    int admission_meta_ok = 1;
    if (!ctx->cache_context.recent.keys || !ctx->cache_context.recent.ns_timestamps
        || !ctx->cache_context.segments.slot_hit_count || !ctx->cache_context.segments.slot_hot)
    {
        admission_meta_ok = 0;
    }

    for (int i = 0; i < 4; i++) {
        ctx->cache_context.sketch.rows[i] = calloc(ctx->cache_context.sketch.width, sizeof(uint16_t));
        if (!ctx->cache_context.sketch.rows[i])
            admission_meta_ok = 0;
    }

    if (!admission_meta_ok) {
        fprintf(stderr, "[Cache] Admission metadata allocation failed, disabling admission/pressure mode\n");

        free(ctx->cache_context.recent.keys);
        ctx->cache_context.recent.keys = NULL;
        free(ctx->cache_context.recent.ns_timestamps);
        ctx->cache_context.recent.ns_timestamps = NULL;
        free(ctx->cache_context.segments.slot_hit_count);
        ctx->cache_context.segments.slot_hit_count = NULL;
        free(ctx->cache_context.segments.slot_hot);
        ctx->cache_context.segments.slot_hot = NULL;
        for (int i = 0; i < 4; i++) {
            free(ctx->cache_context.sketch.rows[i]);
            ctx->cache_context.sketch.rows[i] = NULL;
        }

        ctx->cache_context.recent.capacity = 0;
        ctx->cache_context.sketch.width = 0;
        ctx->cache_context.sketch.ops = 0;
        ctx->cache_context.admission.enabled = 0;
        ctx->cache_context.admission.pressure_mode = 0;
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

    ctx->rb_log = ring_buffer__new(bpf_map__fd(ctx->skel->maps._rb_log), print_bpf_log, &ctx->log_opt, NULL);
    if (!ctx->rb_log) {
        fprintf(stderr, "Failed to create ring buffer: rb_log\n");
        err = ERR_RB_CREATE;
        goto cleanup;
    }
#else
    (void)env->log_level; /* unused when logging disabled */
#endif

    int ifindex = (int)if_nametoindex(env->interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name: %s\n", env->interface);
        err = ERR_INVALID_IFACE;
        goto cleanup;
    }

    int attached = 0;
    for (int attempt = 0; attempt < ATTACH_RETRY_MAX; attempt++) {
        ctx->skel->links.xdp_rx = bpf_program__attach_xdp(ctx->skel->progs.xdp_rx, ifindex);
        if (ctx->skel->links.xdp_rx) {
            attached = 1;
            break;
        }
        err = -errno;

        ctx->skel->links.xdp_rx = NULL;
        int backoff_ms = ATTACH_RETRY_BASE_MS << attempt;
        if (backoff_ms > ATTACH_RETRY_MAX_MS) {
            backoff_ms = ATTACH_RETRY_MAX_MS;
        }

        fprintf(
            stderr,
            "Attach retry (XDP) attempt %d/%d failed: %d, backoff=%dms\n",
            attempt + 1,
            ATTACH_RETRY_MAX,
            err,
            backoff_ms
        );
        usleep((useconds_t)backoff_ms * 1000U);
    }

    if (!attached) {
        err = ERR_XDP_ATTACH;
        goto cleanup;
    }

    attached = 0;
    for (int attempt = 0; attempt < ATTACH_RETRY_MAX; attempt++) {
        ctx->skel->links.tc_tx = bpf_program__attach_tcx(ctx->skel->progs.tc_tx, ifindex, NULL);
        if (ctx->skel->links.tc_tx) {
            attached = 1;
            break;
        }
        err = -errno;

        if (is_tcx_not_supported_err(err)) {
            fprintf(stderr, "TCX not supported on %s, falling back to TC\n", env->interface);
            ctx->skel->links.tc_tx = NULL;
            err = attach_tc_legacy(ctx, ifindex);
            if (!err) {
                attached = 1;
                break;
            }
            fprintf(stderr, "Legacy TC fallback attach failed: %d\n", err);
        }

        ctx->skel->links.tc_tx = NULL;
        int backoff_ms = ATTACH_RETRY_BASE_MS << attempt;
        if (backoff_ms > ATTACH_RETRY_MAX_MS) {
            backoff_ms = ATTACH_RETRY_MAX_MS;
        }

        fprintf(
            stderr,
            "Attach retry (TC) attempt %d/%d failed: %d, backoff=%dms\n",
            attempt + 1,
            ATTACH_RETRY_MAX,
            err,
            backoff_ms
        );
        usleep((useconds_t)backoff_ms * 1000U);
    }

    if (!attached) {
        err = ERR_TC_ATTACH;
        goto cleanup;
    }

    ctx->rb_pkt =
        ring_buffer__new(bpf_map__fd(ctx->skel->maps.rb_pkt), dns_parser_handle_event, &ctx->parser_context, NULL);
    if (!ctx->rb_pkt) {
        fprintf(stderr, "Failed to create ring buffer: rb_pkt\n");
        err = ERR_RB_CREATE;
        goto cleanup;
    }

    printf("Successfully attached to interface: %s (ifindex: %d)\n", env->interface, ifindex);

    return 0;

cleanup:
    loader_cleanup_bpf(ctx);
    return err;
}

int loader_poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms) {
    int ret = ring_buffer__poll(ctx->rb_pkt, timeout_ms);
    return ret;
}

int loader_dump_bpf_log([[maybe_unused]] struct bpf_ctx* ctx, [[maybe_unused]] int timeout_ms) {
#if SHINKU_BPF_LOG_ENABLED
    return ring_buffer__poll(ctx->rb_log, timeout_ms);
#else
    return 0;
#endif
}

void loader_cleanup_bpf(struct bpf_ctx* ctx) {
    loader_stop_cleanup_thread(ctx);

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

    free(ctx->cache_context.slot_owners);
    ctx->cache_context.slot_owners = NULL;
    free(ctx->cache_context.recent.keys);
    ctx->cache_context.recent.keys = NULL;
    free(ctx->cache_context.recent.ns_timestamps);
    ctx->cache_context.recent.ns_timestamps = NULL;
    free(ctx->cache_context.segments.slot_hit_count);
    ctx->cache_context.segments.slot_hit_count = NULL;
    free(ctx->cache_context.segments.slot_hot);
    ctx->cache_context.segments.slot_hot = NULL;
    for (int i = 0; i < 4; i++) {
        free(ctx->cache_context.sketch.rows[i]);
        ctx->cache_context.sketch.rows[i] = NULL;
    }

    if (ctx->skel) {
        cache_bpf__destroy(ctx->skel);
        ctx->skel = NULL;
    }

    if (ctx->cache_context.slot_owners_lock) {
        ctx->cache_context.slot_owners_lock = NULL;
        pthread_mutex_destroy(&ctx->cache_lock);
    }

    if (ctx->cleanup_wait_sync_initialized) {
        pthread_cond_destroy(&ctx->cleanup_wait_cond);
        pthread_mutex_destroy(&ctx->cleanup_wait_lock);
        ctx->cleanup_wait_sync_initialized = false;
    }
}

/* ============================================================================
 * Cleanup Thread
 * ============================================================================ */

/**
 * @brief Background thread function for periodic cache cleanup.
 * @param arg BPF context pointer.
 * @return NULL on thread exit.
 *
 * Runs in a loop, calling cache_cleanup_expired_entries() at configured
 * intervals until cleanup_running flag is cleared.
 */
static void* cleanup_thread_func(void* arg) {
    struct bpf_ctx* ctx = arg;

    while (atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire)) {
        if (ctx->cleanup_wait_sync_initialized) {
            struct timespec wake_at;
            if (clock_gettime(CLOCK_REALTIME, &wake_at) == 0) {
                wake_at.tv_sec += (time_t)(ctx->cleanup_cfg.interval_ms / 1000U);
                wake_at.tv_nsec += (long)(ctx->cleanup_cfg.interval_ms % 1000U) * 1000000L;
                if (wake_at.tv_nsec >= 1000000000L) {
                    wake_at.tv_sec++;
                    wake_at.tv_nsec -= 1000000000L;
                }

                pthread_mutex_lock(&ctx->cleanup_wait_lock);
                if (!atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire)) {
                    pthread_mutex_unlock(&ctx->cleanup_wait_lock);
                    break;
                }

                pthread_cond_timedwait(&ctx->cleanup_wait_cond, &ctx->cleanup_wait_lock, &wake_at);
                bool should_run = atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire);
                pthread_mutex_unlock(&ctx->cleanup_wait_lock);
                if (!should_run)
                    break;
            }
        } else {
            struct timespec sleep_time = {
                .tv_sec = (time_t)(ctx->cleanup_cfg.interval_ms / 1000U),
                .tv_nsec = (long)(ctx->cleanup_cfg.interval_ms % 1000U) * 1000000L,
            };
            nanosleep(&sleep_time, NULL);
            if (!atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire)) {
                break;
            }
        }

        int removed = dns_parser_cleanup_expired_entries(&ctx->cache_context);
        (void)removed;
    }

    return NULL;
}

int loader_start_cleanup_thread(struct bpf_ctx* ctx, uint32_t interval_ms) {
    if (interval_ms == 0) {
        interval_ms = 10000; /* Default: 10 seconds */
    }

    ctx->cleanup_cfg.interval_ms = interval_ms;
    atomic_store_explicit(&ctx->cleanup_running, true, memory_order_release);

    int err = pthread_create(&ctx->cleanup_thread, NULL, cleanup_thread_func, ctx);
    if (err != 0) {
        fprintf(stderr, "Failed to create cleanup thread: %d\n", err);
        atomic_store_explicit(&ctx->cleanup_running, false, memory_order_release);
        return -err;
    }

    printf("Started cleanup thread (interval: %ums)\n", interval_ms);
    return 0;
}

void loader_stop_cleanup_thread(struct bpf_ctx* ctx) {
    if (!atomic_load_explicit(&ctx->cleanup_running, memory_order_acquire))
        return;

    atomic_store_explicit(&ctx->cleanup_running, false, memory_order_release);

    if (ctx->cleanup_wait_sync_initialized) {
        pthread_mutex_lock(&ctx->cleanup_wait_lock);
        pthread_cond_signal(&ctx->cleanup_wait_cond);
        pthread_mutex_unlock(&ctx->cleanup_wait_lock);
    }

    pthread_join(ctx->cleanup_thread, NULL);
    printf("Cleanup thread stopped\n");
}
