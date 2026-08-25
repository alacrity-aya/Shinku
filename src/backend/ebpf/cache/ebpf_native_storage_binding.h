// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <span>
#include <utility>

namespace shinku::backend::ebpf {

/// RAII binding of a cache-map file descriptor to a mapped BPF arena span.
class EbpfNativeStorageBinding {
public:
    /// @brief Bind cache map fd @p cache_map_fd to the arena span @p arena.
    EbpfNativeStorageBinding(int cache_map_fd, std::span<std::byte> arena) noexcept:
        cache_map_fd_(cache_map_fd),
        arena_(arena) {}

    EbpfNativeStorageBinding(const EbpfNativeStorageBinding&) = delete;
    EbpfNativeStorageBinding& operator=(const EbpfNativeStorageBinding&) = delete;

    /// @brief Move-construct, stealing the fd and arena span from @p other.
    EbpfNativeStorageBinding(EbpfNativeStorageBinding&& other) noexcept:
        cache_map_fd_(std::exchange(other.cache_map_fd_, -1)),
        arena_(std::exchange(other.arena_, {})) {}

    /// @brief Move-assign, stealing the fd and arena span from @p other.
    EbpfNativeStorageBinding& operator=(EbpfNativeStorageBinding&& other) noexcept {
        if (this != &other) {
            cache_map_fd_ = std::exchange(other.cache_map_fd_, -1);
            arena_ = std::exchange(other.arena_, {});
        }
        return *this;
    }

    /// @return The owned cache-map file descriptor (or -1 if moved-from).
    [[nodiscard]] int cache_map_fd() const noexcept {
        return cache_map_fd_;
    }
    /// @return A span over the mapped BPF arena (empty if moved-from).
    [[nodiscard]] std::span<std::byte> arena() const noexcept {
        return arena_;
    }

private:
    int cache_map_fd_; ///< The BPF cache map fd, or -1 when moved-from.
    std::span<std::byte> arena_; ///< The mapped arena span, empty when moved-from.
};

} // namespace shinku::backend::ebpf
