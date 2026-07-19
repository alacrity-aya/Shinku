// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "legacy_ebpf_runner.h"

#include "core/loader.h"
#include <errno.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <unistd.h>

static int has_effective_cap(cap_t caps, cap_value_t cap) {
    cap_flag_value_t flag = CAP_CLEAR;
    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &flag) != 0)
        return 0;
    return flag == CAP_SET;
}

static int check_runtime_privileges(void) {
    if (geteuid() == 0)
        return 0;

    if (!CAP_IS_SUPPORTED(CAP_BPF)) {
        fprintf(stderr, "Kernel does not support CAP_BPF. Run as root or upgrade kernel/libcap.\n");
        return -1;
    }

    cap_t caps = cap_get_proc();
    if (!caps) {
        perror("cap_get_proc");
        return -1;
    }

    int ok = has_effective_cap(caps, CAP_BPF) && has_effective_cap(caps, CAP_NET_ADMIN)
        && has_effective_cap(caps, CAP_SYS_ADMIN);
    cap_free(caps);

    if (!ok) {
        fprintf(
            stderr,
            "Insufficient privileges. Run as root, or grant capabilities:\n"
            "  sudo setcap cap_sys_admin,cap_net_admin,cap_bpf=eip ./shinku\n"
        );
        return -1;
    }
    return 0;
}

int shinku_run_legacy_ebpf(
    const struct env* env,
    shinku_shutdown_requested_fn shutdown_requested,
    void* shutdown_user_data
) {
    if (!env || !shutdown_requested)
        return 1;

    struct bpf_ctx ctx = { 0 };
    int err = check_runtime_privileges();
    if (err)
        return 1;

    err = loader_setup_bpf(&ctx, env);
    if (err)
        goto cleanup;

    err = loader_start_cleanup_thread(&ctx, env->cleanup_interval_ms);
    if (err) {
        fprintf(stderr, "Cleanup thread unavailable, continuing: %d\n", err);
        err = 0;
    }

    printf("BPF System Running... Press Ctrl+C to stop.\n");

    while (!shutdown_requested(shutdown_user_data)) {
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
            fprintf(stderr, "Error polling pkt ring buffer: %d (continuing)\n", err);
            usleep(50000);
            continue;
        }
    }

cleanup:
    printf("\nShutting down...\n");
    loader_cleanup_bpf(&ctx);
    return err < 0 ? -err : 0;
}
