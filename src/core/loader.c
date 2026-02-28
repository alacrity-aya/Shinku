// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "loader.h"

#include "bpf_log.h"
#include "cache.skel.h"
#include "constants.h"
#include "dns_parser.h"
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <net/if.h>
#include <stdio.h>

#include <time.h>

// Error codes for setup_bpf
#define ERR_SKEL_LOAD -1
#define ERR_RB_CREATE -2
#define ERR_INVALID_IFACE -3
#define ERR_XDP_ATTACH -4
#define ERR_TC_ATTACH -5


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

    bpf_program__set_autoattach(ctx->skel->progs.tc_tx, false);

    /* Load BPF programs and create maps */
    err = cache_bpf__load(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        err = ERR_SKEL_LOAD;
        goto cleanup;
    }

    /* Wire up cache context — skeleton auto-mmap's arena via __arena globals */
    ctx->cache_ctx.entries = ctx->skel->arena->cache_entries;
    ctx->cache_ctx.next_idx = &ctx->skel->arena->next_entry_idx;
    ctx->cache_ctx.max_entries = CACHE_MAP_MAX_ENTRIES;
    ctx->cache_ctx.cache_map_fd = bpf_map__fd(ctx->skel->maps.cache_map);

    err = cache_bpf__attach(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    #ifdef ENABLE_BPF_LOG
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
    (void)env->log_level;  /* unused when logging disabled */
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

    printf("Successfully attached to interface: %s (ifindex: %d)\n", env->interface, ifindex);

    return 0;

cleanup:
    cleanup_bpf(ctx);
    return err;
}

int poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms) {
    return ring_buffer__poll(ctx->rb_pkt, timeout_ms);
}

int dump_bpf_log(struct bpf_ctx* ctx, int timeout_ms) {
#ifdef ENABLE_BPF_LOG
    return ring_buffer__poll(ctx->rb_log, timeout_ms);
#else
    (void)ctx;
    (void)timeout_ms;
    return 0;
#endif
}

void cleanup_bpf(struct bpf_ctx* ctx) {
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

    if (ctx->skel) {
        cache_bpf__destroy(ctx->skel);
        ctx->skel = NULL;
    }
}
