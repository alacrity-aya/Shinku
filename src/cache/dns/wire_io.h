// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace shinku::cache::dns::wire {

// Callers validate that the fixed-width field is present before accessing it.
inline uint16_t read_u16(std::span<const std::byte> bytes, size_t offset) noexcept {
    return static_cast<uint16_t>(static_cast<uint16_t>(std::to_integer<uint8_t>(bytes[offset])) << 8U)
        | std::to_integer<uint8_t>(bytes[offset + 1]);
}

inline uint32_t read_u32(std::span<const std::byte> bytes, size_t offset) noexcept {
    return static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset])) << 24U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset + 1])) << 16U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset + 2])) << 8U
        | std::to_integer<uint8_t>(bytes[offset + 3]);
}

inline void write_u32(std::span<std::byte> bytes, size_t offset, uint32_t value) noexcept {
    bytes[offset] = static_cast<std::byte>(value >> 24U);
    bytes[offset + 1] = static_cast<std::byte>(value >> 16U);
    bytes[offset + 2] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 3] = static_cast<std::byte>(value);
}

} // namespace shinku::cache::dns::wire
