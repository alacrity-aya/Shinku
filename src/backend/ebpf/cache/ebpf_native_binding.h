// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/cache/ebpf_native_storage_binding.h"

#include <utility>

namespace shinku::backend::ebpf {

class EbpfNativePendingBinding {
public:
    explicit EbpfNativePendingBinding(int pending_map_fd) noexcept: pending_map_fd_(pending_map_fd) {}

    EbpfNativePendingBinding(const EbpfNativePendingBinding&) = delete;
    EbpfNativePendingBinding& operator=(const EbpfNativePendingBinding&) = delete;

    EbpfNativePendingBinding(EbpfNativePendingBinding&& other) noexcept:
        pending_map_fd_(std::exchange(other.pending_map_fd_, -1)) {}

    EbpfNativePendingBinding& operator=(EbpfNativePendingBinding&& other) noexcept {
        if (this != &other)
            pending_map_fd_ = std::exchange(other.pending_map_fd_, -1);
        return *this;
    }

    [[nodiscard]] int pending_map_fd() const noexcept {
        return pending_map_fd_;
    }

private:
    int pending_map_fd_;
};

class EbpfNativeBinding {
public:
    EbpfNativeBinding(EbpfNativeStorageBinding cache, EbpfNativePendingBinding pending) noexcept:
        cache_(std::move(cache)),
        pending_(std::move(pending)) {}

    EbpfNativeBinding(const EbpfNativeBinding&) = delete;
    EbpfNativeBinding& operator=(const EbpfNativeBinding&) = delete;
    EbpfNativeBinding(EbpfNativeBinding&&) noexcept = default;
    EbpfNativeBinding& operator=(EbpfNativeBinding&&) noexcept = default;

    [[nodiscard]] EbpfNativeStorageBinding take_cache() noexcept {
        return std::move(cache_);
    }
    [[nodiscard]] EbpfNativePendingBinding take_pending() noexcept {
        return std::move(pending_);
    }

private:
    EbpfNativeStorageBinding cache_;
    EbpfNativePendingBinding pending_;
};

} // namespace shinku::backend::ebpf
