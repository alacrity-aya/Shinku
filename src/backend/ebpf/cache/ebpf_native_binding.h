// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_native_storage_binding.h"

#include <utility>

namespace shinku::backend::ebpf {

/// RAII handle to the BPF pending-query map file descriptor.
class EbpfNativePendingBinding {
public:
    /// @brief Take ownership of the pending-query map file descriptor @p pending_map_fd.
    explicit EbpfNativePendingBinding(int pending_map_fd) noexcept: pending_map_fd_(pending_map_fd) {}

    EbpfNativePendingBinding(const EbpfNativePendingBinding&) = delete;
    EbpfNativePendingBinding& operator=(const EbpfNativePendingBinding&) = delete;

    /// @brief Move-construct, stealing the fd from @p other and leaving it as -1.
    EbpfNativePendingBinding(EbpfNativePendingBinding&& other) noexcept:
        pending_map_fd_(std::exchange(other.pending_map_fd_, -1)) {}

    /// @brief Move-assign, stealing the fd from @p other and leaving it as -1.
    EbpfNativePendingBinding& operator=(EbpfNativePendingBinding&& other) noexcept {
        if (this != &other)
            pending_map_fd_ = std::exchange(other.pending_map_fd_, -1);
        return *this;
    }

    /// @return The owned pending-query map file descriptor (or -1 if moved-from).
    [[nodiscard]] int pending_map_fd() const noexcept {
        return pending_map_fd_;
    }

private:
    int pending_map_fd_; ///< The BPF pending-query map fd, or -1 when moved-from.
};

/// Aggregate of the two native bindings (cache + pending) produced by skeleton preparation.
class EbpfNativeBinding {
public:
    /// @brief Construct the aggregate binding from its cache and pending parts.
    EbpfNativeBinding(EbpfNativeStorageBinding cache, EbpfNativePendingBinding pending) noexcept:
        cache_(std::move(cache)),
        pending_(std::move(pending)) {}

    EbpfNativeBinding(const EbpfNativeBinding&) = delete;
    EbpfNativeBinding& operator=(const EbpfNativeBinding&) = delete;
    EbpfNativeBinding(EbpfNativeBinding&&) noexcept = default;
    EbpfNativeBinding& operator=(EbpfNativeBinding&&) noexcept = default;

    /// @brief Move out the cache storage binding.
    [[nodiscard]] EbpfNativeStorageBinding take_cache() noexcept {
        return std::move(cache_);
    }
    /// @brief Move out the pending-query map binding.
    [[nodiscard]] EbpfNativePendingBinding take_pending() noexcept {
        return std::move(pending_);
    }

private:
    EbpfNativeStorageBinding cache_; ///< Cache storage binding (arena + map fd).
    EbpfNativePendingBinding pending_; ///< Pending-query map binding.
};

} // namespace shinku::backend::ebpf
