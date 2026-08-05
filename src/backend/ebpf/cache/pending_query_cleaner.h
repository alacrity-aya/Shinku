// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_native_binding.h"
#include "backend/ebpf/cache/ebpf_pending_query_map.h"
#include "cache/cache_time.h"
#include "ebpf_cache_abi.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>

namespace shinku::backend::ebpf {

struct PendingCleanupResult {
    size_t removed_entries;
    bool more_work;
};

class PendingQueryCleaner {
public:
    static constexpr size_t kBatchSize = 256;

    [[nodiscard]] static std::unique_ptr<PendingQueryCleaner>
    create(EbpfNativePendingBinding binding, std::chrono::nanoseconds timeout);

    [[nodiscard]] static std::unique_ptr<PendingQueryCleaner> create_for_testing(
        EbpfNativePendingBinding binding,
        std::chrono::nanoseconds timeout,
        std::unique_ptr<EbpfPendingQueryMap> map
    );

    [[nodiscard]] std::expected<PendingCleanupResult, std::error_code> cleanup(cache::CacheTime now) noexcept;

private:
    PendingQueryCleaner(
        EbpfNativePendingBinding binding,
        std::chrono::nanoseconds timeout,
        std::unique_ptr<EbpfPendingQueryMap> map
    ) noexcept;

    [[nodiscard]] bool expired(const ebpf_pending_query_value& value, uint64_t now_ns) const noexcept;

    EbpfNativePendingBinding binding_;
    uint64_t timeout_ns_;
    std::unique_ptr<EbpfPendingQueryMap> map_;
    std::optional<ebpf_pending_query_key> cursor_;
    std::array<ebpf_pending_query_key, kBatchSize> keys_ {};
    std::array<ebpf_pending_query_value, kBatchSize> values_ {};
};

} // namespace shinku::backend::ebpf
