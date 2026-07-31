// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <span>
#include <utility>

namespace shinku::backend::ebpf {

class EbpfNativeStorageBinding {
public:
    EbpfNativeStorageBinding(int cache_map_fd, std::span<std::byte> arena) noexcept:
        cache_map_fd_(cache_map_fd),
        arena_(arena) {}

    EbpfNativeStorageBinding(const EbpfNativeStorageBinding&) = delete;
    EbpfNativeStorageBinding& operator=(const EbpfNativeStorageBinding&) = delete;

    EbpfNativeStorageBinding(EbpfNativeStorageBinding&& other) noexcept:
        cache_map_fd_(std::exchange(other.cache_map_fd_, -1)),
        arena_(std::exchange(other.arena_, {})) {}

    EbpfNativeStorageBinding& operator=(EbpfNativeStorageBinding&& other) noexcept {
        if (this != &other) {
            cache_map_fd_ = std::exchange(other.cache_map_fd_, -1);
            arena_ = std::exchange(other.arena_, {});
        }
        return *this;
    }

    [[nodiscard]] int cache_map_fd() const noexcept {
        return cache_map_fd_;
    }
    [[nodiscard]] std::span<std::byte> arena() const noexcept {
        return arena_;
    }

private:
    int cache_map_fd_;
    std::span<std::byte> arena_;
};

} // namespace shinku::backend::ebpf
