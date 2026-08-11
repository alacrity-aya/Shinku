// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace shinku::cache {

enum class CacheStoreErrorCode : uint8_t {
    StorageUnavailable,
    WriteFailed,
    CleanupFailed,
};

struct CacheStoreError {
    CacheStoreErrorCode code;
    std::optional<std::error_code> cause;
};

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
