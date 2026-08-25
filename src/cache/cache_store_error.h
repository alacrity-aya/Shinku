// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace shinku::cache {

/// Failure codes returned by @ref cache::CacheStore operations.
enum class CacheStoreErrorCode : uint8_t {
    StorageUnavailable, ///< No storage backend is available to satisfy the request.
    WriteFailed, ///< An attempt to write a cache entry failed.
    CleanupFailed, ///< An attempt to remove expired entries failed.
};

/// Error returned by @ref cache::CacheStore operations, carrying an optional cause.
struct CacheStoreError {
    CacheStoreErrorCode code; ///< The failure category.
    std::optional<std::error_code> cause; ///< Underlying system error, if any.
};

/**
 * @brief Return a lowercase human-readable name for a @ref CacheStoreErrorCode.
 *
 * @param code The error code to name.
 * @return A stable string view naming the code.
 */
[[nodiscard]] constexpr std::string_view cache_store_error_name(CacheStoreErrorCode code) noexcept {
    switch (code) {
        case CacheStoreErrorCode::StorageUnavailable:
            return "storage unavailable";
        case CacheStoreErrorCode::WriteFailed:
            return "write failed";
        case CacheStoreErrorCode::CleanupFailed:
            return "cleanup failed";
    }
    std::unreachable();
}

} // namespace shinku::cache
