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

/// Result of a @ref PendingQueryCleaner::cleanup sweep.
struct PendingCleanupResult {
    size_t removed_entries; ///< Number of pending entries removed.
    bool more_work; ///< True if more stale entries remain for a follow-up sweep.
};

/**
 * @brief Reaps stale pending-query entries from the BPF pending-query map.
 *
 * Walks the map in bounded batches, erasing entries older than the configured
 * timeout, so the cleanup worker can make progress without monopolizing the
 * data plane.
 */
class PendingQueryCleaner {
public:
    static constexpr size_t kBatchSize = 256; ///< Maximum entries examined per cleanup call.

    /// @brief Construct a cleaner for production, backed by a real BPF map.
    [[nodiscard]] static std::unique_ptr<PendingQueryCleaner>
    create(EbpfNativePendingBinding binding, std::chrono::nanoseconds timeout);

    /// @brief Construct a cleaner with an injected map, for tests only.
    [[nodiscard]] static std::unique_ptr<PendingQueryCleaner> create_for_testing(
        EbpfNativePendingBinding binding,
        std::chrono::nanoseconds timeout,
        std::unique_ptr<EbpfPendingQueryMap> map
    );

    /**
     * @brief Sweep stale pending entries.
     * @param now The current cache time.
     * @return The cleanup result, or a std::error_code on failure.
     */
    [[nodiscard]] std::expected<PendingCleanupResult, std::error_code> cleanup(cache::CacheTime now) noexcept;

private:
    PendingQueryCleaner(
        EbpfNativePendingBinding binding,
        std::chrono::nanoseconds timeout,
        std::unique_ptr<EbpfPendingQueryMap> map
    ) noexcept;

    /// @brief Return true if @p value is older than the timeout as of @p now_ns.
    [[nodiscard]] bool expired(const ebpf_pending_query_value& value, uint64_t now_ns) const noexcept;

    EbpfNativePendingBinding binding_; ///< Ownership of the pending-query map fd.
    uint64_t timeout_ns_; ///< Pending-query timeout in nanoseconds.
    std::unique_ptr<EbpfPendingQueryMap> map_; ///< The BPF map (or test double).
    std::optional<ebpf_pending_query_key> cursor_; ///< Resume cursor for the next batch.
    std::array<ebpf_pending_query_key, kBatchSize> keys_ {}; ///< Scratch for the current batch's keys.
    std::array<ebpf_pending_query_value, kBatchSize> values_ {}; ///< Scratch for the current batch's values.
};

} // namespace shinku::backend::ebpf
