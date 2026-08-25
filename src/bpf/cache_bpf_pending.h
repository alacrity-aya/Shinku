// SPDX-License-Identifier: GPL-2.0-only
/* Pending-query tracking for the cache BPF program. */
#pragma once

#include "bpf/cache_bpf_fingerprint.h"

/**
 * @brief Record or refresh a pending-query entry for a query just passed through.
 *
 * Inserts with BPF_NOEXIST so a racing same-key query keeps the first entry;
 * otherwise the last-seen timestamp is advanced by CAS, retried once, provided
 * the entry is unclaimed and its fingerprint matches. Skipped entirely when @p now
 * collides with the claimed bit (top bit set).
 * @param key The pending-query key (4-tuple plus transaction id).
 * @param fingerprint Fingerprint of the pending question.
 * @param now Current boot time in nanoseconds.
 */
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
