// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>

namespace shinku::backend::ebpf {

/// Whether an @ref EbpfCacheMap::update is inserting a new key or updating an existing one.
enum class EbpfCacheMapUpdateMode : uint8_t {
    Insert, ///< Insert a new key; the key must not already be present.
    Update, ///< Update an existing key; the key must already be present.
};

/**
 * @brief Abstract BPF hash map mapping physical keys to cache publications.
 *
 * This is the seam between the host store and the BPF map (or a test double),
 * exposing lookup, update, and erase over the shared physical-key space.
 */
class EbpfCacheMap {
public:
    virtual ~EbpfCacheMap() = default;

    /// @brief Look up the publication stored for @p key, if any.
    /// @return The publication, empty if absent, or a std::error_code on failure.
    [[nodiscard]] virtual std::expected<std::optional<ebpf_cache_publication>, std::error_code>
    lookup(const ebpf_cache_physical_key& key) noexcept = 0;

    /// @brief Insert or update the publication for @p key according to @p mode.
    [[nodiscard]] virtual std::expected<void, std::error_code> update(
        const ebpf_cache_physical_key& key,
        const ebpf_cache_publication& publication,
        EbpfCacheMapUpdateMode mode
    ) noexcept = 0;

    /// @brief Erase the publication for @p key, if present.
    [[nodiscard]] virtual std::expected<void, std::error_code> erase(const ebpf_cache_physical_key& key) noexcept = 0;
};

/**
 * @brief Construct a production @ref EbpfCacheMap backed by a real BPF map.
 * @param map_fd File descriptor of the BPF hash map.
 * @return A map instance wrapping @p map_fd.
 */
[[nodiscard]] std::unique_ptr<EbpfCacheMap> make_production_ebpf_cache_map(int map_fd);

} // namespace shinku::backend::ebpf
