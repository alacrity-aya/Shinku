// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>

namespace shinku::backend::ebpf {

enum class EbpfCacheMapUpdateMode : uint8_t {
    Insert,
    Update,
};

class EbpfCacheMap {
public:
    virtual ~EbpfCacheMap() = default;

    [[nodiscard]] virtual std::expected<std::optional<ebpf_cache_publication>, std::error_code>
    lookup(const ebpf_cache_physical_key& key) noexcept = 0;

    [[nodiscard]] virtual std::expected<void, std::error_code> update(
        const ebpf_cache_physical_key& key,
        const ebpf_cache_publication& publication,
        EbpfCacheMapUpdateMode mode
    ) noexcept = 0;

    [[nodiscard]] virtual std::expected<void, std::error_code> erase(const ebpf_cache_physical_key& key) noexcept = 0;
};

[[nodiscard]] std::expected<std::unique_ptr<EbpfCacheMap>, std::error_code>
make_production_ebpf_cache_map(int map_fd) noexcept;

} // namespace shinku::backend::ebpf
