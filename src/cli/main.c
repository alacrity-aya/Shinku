// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config.h"
#include "core/loader.h"
#include <ares.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static volatile bool exiting = false;

#define CLEANUP_INTERVAL_NS (10ULL * 1000000000ULL)

static void sig_handler([[maybe_unused]] int sig) {
    exiting = true;
}

int main(int argc, char** argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return -1;
    }

    struct env env = { 0 };
    struct bpf_ctx ctx = { 0 };
    int err;

    err = parse_args(argc, argv, &env);
    if (err)
        return err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = setup_bpf(&ctx, &env);
    if (err)
        goto cleanup;

    printf("BPF System Running... Press Ctrl+C to stop.\n");

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t last_cleanup_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;

    while (!exiting) {
        err = dump_bpf_log(&ctx, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling log ring buffer: %d\n", err);
            goto cleanup;
        }

        err = poll_pkt_ring(&ctx, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling pkt ring buffer: %d\n", err);
            goto cleanup;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
        if (now_ns - last_cleanup_ns >= CLEANUP_INTERVAL_NS) {
            cleanup_expired_entries(&ctx.cache_ctx);
            last_cleanup_ns = now_ns;
        }
    }

cleanup:
    printf("\nShutting down...\n");
    cleanup_bpf(&ctx);
    return err < 0 ? -err : 0;
}
