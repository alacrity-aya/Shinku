#include "loader.h"

#include "cache.skel.h"
#include "parser.h"
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <common/bpf_log.h>
#include <net/if.h>
#include <stdio.h>
#include <time.h>

//TODO: move this function to bpf_log.h
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_GRAY "\033[1;90m"

    char ts[16];
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);

    const char* color_code = COLOR_RESET;
    const char* level_str = "INFO";

    switch (level) {
        case LIBBPF_WARN:
            color_code = COLOR_YELLOW;
            level_str = "WARN";
            break;
        case LIBBPF_INFO:
            color_code = COLOR_GREEN;
            level_str = "INFO";
            break;
        case LIBBPF_DEBUG:
            color_code = COLOR_GRAY;
            level_str = "DEBUG";

            // NOTE: skip debug message
            return 0;
            break;
        default:
            color_code = COLOR_RED;
            level_str = "ERROR";
            break;
    }

    fprintf(stderr, "%s[%s] [%s] ", color_code, ts, level_str);

    int ret = vfprintf(stderr, format, args);

    fprintf(stderr, "%s", COLOR_RESET);

    return ret;

#undef COLOR_RESET
#undef COLOR_RED
#undef COLOR_YELLOW
#undef COLOR_GREEN
#undef COLOR_GRAY
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

    ctx->skel = cache_bpf__open_and_load();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    bpf_program__set_autoattach(ctx->skel->progs.tc_tx, false);

    err = cache_bpf__attach(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return err;
    }

    // rb_log
    ctx->log_opt.min_level = env->log_level;
    ctx->log_opt.show_timestamp = true;
    ctx->log_opt.use_color = true;

    ctx->rb_log =
        ring_buffer__new(bpf_map__fd(ctx->skel->maps._rb_log), print_bpf_log, &ctx->log_opt, NULL);
    if (!ctx->rb_log) {
        fprintf(stderr, "Failed to create ring buffer: rb_log\n");
        return -1;
    }

    // xdp
    uint32_t ifindex = if_nametoindex(env->interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name: %s\n", env->interface);
        return -1;
    }

    ctx->skel->links.xdp_rx = bpf_program__attach_xdp(ctx->skel->progs.xdp_rx, ifindex);
    err = libbpf_get_error(ctx->skel->links.xdp_rx);
    if (err) {
        fprintf(stderr, "Failed to attach XDP(Ingress) to %s (Error: %d)\n", env->interface, err);
        ctx->skel->links.xdp_rx = NULL;
        return -1;
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
                return -1;
            }
        } else {
            ctx->skel->links.tc_tx = NULL;
            return -1;
        }
    }

    // rb_pkt
    ctx->rb_pkt = ring_buffer__new(bpf_map__fd(ctx->skel->maps.rb_pkt), handle_packet, NULL, NULL);
    if (!ctx->rb_pkt) {
        fprintf(stderr, "Failed to create ring buffer: rb_pkt\n");
        return -1;
    }

    printf("Successfully attached to interface: %s (ifindex: %d)\n", env->interface, ifindex);

    return 0;
}

int poll_pkt_ring(struct bpf_ctx* ctx, int timeout_ms) {
    return ring_buffer__poll(ctx->rb_pkt, timeout_ms);
}

int dump_bpf_log(struct bpf_ctx* ctx, int timeout_ms) {
    return ring_buffer__poll(ctx->rb_log, timeout_ms);
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
