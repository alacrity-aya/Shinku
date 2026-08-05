// SPDX-License-Identifier: GPL-2.0-only
/* Pending-query tracking for the cache BPF program. */
#pragma once

#include "bpf/cache_bpf_fingerprint.h"

static __always_inline void remember_pending(
    const struct ebpf_pending_query_key* key,
    const struct ebpf_cache_fingerprint* fingerprint,
    __u64 now
) {
    if ((now & SHINKU_EBPF_PENDING_CLAIMED) != 0)
        return;
    struct ebpf_pending_query_value* current = bpf_map_lookup_elem(&pending_queries, key);
    if (!current) {
        const struct ebpf_pending_query_value inserted = {
            .fingerprint = *fingerprint,
            .state_and_last_seen_ns = now,
        };
        (void)bpf_map_update_elem(&pending_queries, key, &inserted, BPF_NOEXIST);
        return;
    }
    if (!same_fingerprint(&current->fingerprint, fingerprint))
        return;

#pragma clang loop unroll(full)
    for (int attempt = 0; attempt < 2; ++attempt) {
        const __u64 state_and_observed = READ_ONCE(current->state_and_last_seen_ns);
        if ((state_and_observed & SHINKU_EBPF_PENDING_CLAIMED) != 0)
            return;
        if (__sync_val_compare_and_swap(&current->state_and_last_seen_ns, state_and_observed, now)
            == state_and_observed)
            return;
    }
}
