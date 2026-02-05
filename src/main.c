#include "bpf_log.h"
#include "cache.skel.h"
#include <bpf/libbpf.h>
#include <signal.h>

static volatile bool exiting = false;

static void sig_handler([[maybe_unused]] int sig) {
    exiting = true;
}

int main() {
    struct cache_bpf* skel = NULL;
    struct ring_buffer* rb = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = cache_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    err = cache_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    struct log_options my_log_cfg = { .min_level = LOG_DEBUG,
                                      .show_timestamp = true,
                                      .use_color = true };

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb_log), print_bpf_log, &my_log_cfg, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("BPF Log Manager Started... Press Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
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
    printf("Cleaning up resources...\n");
    ring_buffer__free(rb);
    cache_bpf__destroy(skel);

    return err;
}
