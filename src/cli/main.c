// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config.h"
#include "core/loader.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @file main.c
 * @brief Main entry point for the Shinku DNS cache daemon.
 */

static volatile bool exiting = false;

/**
 * @brief Signal handler for graceful shutdown.
 * @param sig Signal number (SIGINT or SIGTERM).
 *
 * Sets the exiting flag to trigger clean shutdown.
 */
static void sig_handler([[maybe_unused]] int sig) {
    exiting = true;
}

/**
 * @brief Main entry point for the DNS cache daemon.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, positive error code on failure.
 *
 * Initializes BPF programs, starts the cleanup thread, and enters
 * the main event loop to process DNS packets and logs.
 */
int main(int argc, char** argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return -1;
    }

    struct env env = { 0 };
    struct bpf_ctx ctx = { 0 };
    int err;

    err = config_parse_args(argc, argv, &env);
    if (err)
        return err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = loader_setup_bpf(&ctx, &env);
    if (err)
        goto cleanup;

    err = loader_start_cleanup_thread(&ctx, env.cleanup_interval);
    if (err) {
        fprintf(stderr, "Cleanup thread unavailable, continuing in degraded mode: %d\n", err);
        obs_metrics_mark_degraded(&ctx.metrics, OBS_DEGRADED_CLEANUP_THREAD_DOWN);
        err = 0;
    }

    printf("BPF System Running... Press Ctrl+C to stop.\n");

    while (!exiting) {
        err = loader_dump_bpf_log(&ctx, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0)
            fprintf(stderr, "Error polling log ring buffer: %d (continuing)\n", err);

        err = loader_poll_pkt_ring(&ctx, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling pkt ring buffer: %d (degraded, continuing)\n", err);
            usleep(50000);
            continue;
        }
    }

cleanup:
    printf("\nShutting down...\n");
    loader_cleanup_bpf(&ctx);
    return err < 0 ? -err : 0;
}
