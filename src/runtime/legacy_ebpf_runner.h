// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "legacy_env.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*shinku_shutdown_requested_fn)(void* user_data);

int shinku_run_legacy_ebpf(
    const struct env* env,
    shinku_shutdown_requested_fn shutdown_requested,
    void* shutdown_user_data
);

#ifdef __cplusplus
}
#endif
