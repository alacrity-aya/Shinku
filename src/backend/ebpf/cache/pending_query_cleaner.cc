// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/pending_query_cleaner.h"

#include <cstdint>
#include <memory>
#include <utility>

namespace shinku::backend::ebpf {

PendingQueryCleaner::PendingQueryCleaner(
    EbpfNativePendingBinding binding,
    std::chrono::nanoseconds timeout,
    std::unique_ptr<EbpfPendingQueryMap> map
) noexcept:
    binding_(std::move(binding)),
    timeout_ns_(static_cast<uint64_t>(timeout.count())),
    map_(std::move(map)) {}

std::unique_ptr<PendingQueryCleaner>
PendingQueryCleaner::create(EbpfNativePendingBinding binding, std::chrono::nanoseconds timeout) {
    auto map = make_production_ebpf_pending_query_map(binding.pending_map_fd());
    return create_for_testing(std::move(binding), timeout, std::move(map));
}

std::unique_ptr<PendingQueryCleaner> PendingQueryCleaner::create_for_testing(
    EbpfNativePendingBinding binding,
    std::chrono::nanoseconds timeout,
    std::unique_ptr<EbpfPendingQueryMap> map
) {
    return std::unique_ptr<PendingQueryCleaner>(new PendingQueryCleaner(std::move(binding), timeout, std::move(map)));
}

bool PendingQueryCleaner::expired(const ebpf_pending_query_value& value, uint64_t now_ns) const noexcept {
    const uint64_t last_seen_ns = value.state_and_last_seen_ns & SHINKU_EBPF_PENDING_TIME_MASK;
    return now_ns - last_seen_ns >= timeout_ns_;
}

std::expected<PendingCleanupResult, std::error_code> PendingQueryCleaner::cleanup(cache::CacheTime now) noexcept {
    const uint64_t now_ns = static_cast<uint64_t>(now.time_since_epoch().count());

    ebpf_pending_query_key output_cursor {};
    auto batch = map_->lookup_batch(cursor_ ? &*cursor_ : nullptr, output_cursor, keys_, values_);
    if (!batch) {
        cursor_.reset();
        return std::unexpected(batch.error());
    }

    size_t removed = 0;
    for (size_t index = 0; index < batch->count; ++index) {
        if (!expired(values_[index], now_ns))
            continue;

        auto current = map_->lookup(keys_[index]);
        if (!current) {
            cursor_.reset();
            return std::unexpected(current.error());
        }
        if (!*current || !expired(**current, now_ns))
            continue;

        auto erased = map_->erase(keys_[index]);
        if (!erased) {
            cursor_.reset();
            return std::unexpected(erased.error());
        }
        if (*erased)
            ++removed;
    }

    if (batch->terminal)
        cursor_.reset();
    else
        cursor_ = output_cursor;

    return PendingCleanupResult {
        .removed_entries = removed,
        .more_work = !batch->terminal,
    };
}

} // namespace shinku::backend::ebpf
