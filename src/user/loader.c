#include "loader.h"
#include "cache.skel.h"
#include <common/bpf_log.h>
#include <net/if.h>
#include <stdio.h>

int setup_bpf(struct bpf_ctx* ctx, const struct env* env) {
    int err;

    ctx->skel = cache_bpf__open_and_load();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = cache_bpf__attach(ctx->skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return err;
    }

    ctx->log_opt.min_level = env->log_level;
    ctx->log_opt.show_timestamp = true;
    ctx->log_opt.use_color = true;

    ctx->rb =
        ring_buffer__new(bpf_map__fd(ctx->skel->maps.rb_log), print_bpf_log, &ctx->log_opt, NULL);
    if (!ctx->rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }

    uint32_t ifindex = if_nametoindex(env->interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name: %s\n", env->interface);
        return -1;
    }

    ctx->skel->links.xdp_rx = bpf_program__attach_xdp(ctx->skel->progs.xdp_rx, ifindex);
    if (!ctx->skel->links.xdp_rx) {
        err = libbpf_get_error(ctx->skel->links.xdp_rx);
        fprintf(stderr, "Failed to attach XDP to %s (Error: %d)\n", env->interface, err);
        ctx->skel->links.xdp_rx = NULL;
        return -1;
    }

    printf("Successfully attached to interface: %s (ifindex: %d)\n", env->interface, ifindex);
    return 0;
}

int poll_bpf(struct bpf_ctx* ctx, int timeout_ms) {
    return ring_buffer__poll(ctx->rb, timeout_ms);
}

void cleanup_bpf(struct bpf_ctx* ctx) {
    if (ctx->rb) {
        ring_buffer__free(ctx->rb);
        ctx->rb = NULL;
    }
    if (ctx->skel) {
        cache_bpf__destroy(ctx->skel);
        ctx->skel = NULL;
    }
}
