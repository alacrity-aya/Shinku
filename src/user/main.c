#include "config.h"
#include "loader.h"
#include <signal.h>
#include <stdio.h>

static volatile bool exiting = false;

static void sig_handler(int sig) {
    (void)sig;
    exiting = true;
}

int main(int argc, char** argv) {
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

    while (!exiting) {
        err = poll_bpf(&ctx, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    printf("\nShutting down...\n");
    cleanup_bpf(&ctx);
    return err < 0 ? -err : 0;
}
