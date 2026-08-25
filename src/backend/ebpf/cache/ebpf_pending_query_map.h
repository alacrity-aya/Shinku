// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>

namespace shinku::backend::ebpf {

/// Result of a batched lookup over the pending-query map.
struct EbpfPendingBatchResult {
    size_t count; ///< Number of entries returned in this batch.
    bool terminal; ///< True if the cursor has reached the end of the map.
};

/**
 * @brief Abstract BPF map of in-flight pending DNS queries.
 *
 * Exposes batched lookup (for the cleaner's sweeps) plus point lookup and
 * erase, so the cleaner can walk the map and reap stale entries without
 * holding the data plane.
 */
class EbpfPendingQueryMap {
public:
    virtual ~EbpfPendingQueryMap() = default;

    /**
     * @brief Look up the next batch of pending entries starting at @p input_cursor.
     * @param input_cursor Cursor position to resume from (null to start).
     * @param output_cursor Receives the cursor for the next batch.
     * @param keys Output span for the batch's keys.
     * @param values Output span for the batch's values.
     * @return The batch result, or a std::error_code on failure.
     */
    [[nodiscard]] virtual std::expected<EbpfPendingBatchResult, std::error_code> lookup_batch(
        const ebpf_pending_query_key* input_cursor,
        ebpf_pending_query_key& output_cursor,
        std::span<ebpf_pending_query_key> keys,
        std::span<ebpf_pending_query_value> values
    ) noexcept = 0;

    /// @brief Point-lookup the value for @p key.
    [[nodiscard]] virtual std::expected<std::optional<ebpf_pending_query_value>, std::error_code>
    lookup(const ebpf_pending_query_key& key) noexcept = 0;

    /// @brief Erase the entry for @p key, if present.
    /// @return True if an entry was erased, or a std::error_code on failure.
    [[nodiscard]] virtual std::expected<bool, std::error_code> erase(const ebpf_pending_query_key& key) noexcept = 0;
};

/**
 * @brief Construct a production @ref EbpfPendingQueryMap backed by a real BPF map.
 * @param map_fd File descriptor of the BPF pending-query map.
 * @return A map instance wrapping @p map_fd.
 */
[[nodiscard]] std::unique_ptr<EbpfPendingQueryMap> make_production_ebpf_pending_query_map(int map_fd);

} // namespace shinku::backend::ebpf
