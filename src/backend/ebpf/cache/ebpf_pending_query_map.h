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

struct EbpfPendingBatchResult {
    size_t count;
    bool terminal;
};

class EbpfPendingQueryMap {
public:
    virtual ~EbpfPendingQueryMap() = default;

    [[nodiscard]] virtual std::expected<EbpfPendingBatchResult, std::error_code> lookup_batch(
        const ebpf_pending_query_key* input_cursor,
        ebpf_pending_query_key& output_cursor,
        std::span<ebpf_pending_query_key> keys,
        std::span<ebpf_pending_query_value> values
    ) noexcept = 0;

    [[nodiscard]] virtual std::expected<std::optional<ebpf_pending_query_value>, std::error_code>
    lookup(const ebpf_pending_query_key& key) noexcept = 0;

    [[nodiscard]] virtual std::expected<bool, std::error_code> erase(const ebpf_pending_query_key& key) noexcept = 0;
};

[[nodiscard]] std::unique_ptr<EbpfPendingQueryMap> make_production_ebpf_pending_query_map(int map_fd);

} // namespace shinku::backend::ebpf
