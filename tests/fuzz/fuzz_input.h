// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace shinku::cache::fuzzing {

class FuzzInput {
public:
    FuzzInput(const uint8_t* data, size_t size) noexcept {
        constexpr std::array<uint8_t, 4> kHexPrefix { 'h', 'e', 'x', ':' };
        if (size < kHexPrefix.size() || !std::ranges::equal(std::span(data, kHexPrefix.size()), kHexPrefix)) {
            bytes_ = std::as_bytes(std::span(data, size));
            return;
        }

        size_t encoded_end = size;
        while (encoded_end > kHexPrefix.size()
               && (data[encoded_end - 1] == static_cast<uint8_t>('\n')
                   || data[encoded_end - 1] == static_cast<uint8_t>('\r')))
        {
            --encoded_end;
        }

        const size_t encoded_size = encoded_end - kHexPrefix.size();
        if (encoded_size % 2 != 0 || encoded_size / 2 > decoded_.size()) {
            bytes_ = std::as_bytes(std::span(data, size));
            return;
        }

        for (size_t index = 0; index < encoded_size / 2; ++index) {
            const uint8_t high = nibble(data[kHexPrefix.size() + (index * 2)]);
            const uint8_t low = nibble(data[kHexPrefix.size() + (index * 2) + 1]);
            if (high > 0x0f || low > 0x0f) {
                bytes_ = std::as_bytes(std::span(data, size));
                return;
            }
            decoded_[index] = static_cast<std::byte>((high << 4U) | low);
        }
        bytes_ = std::span<const std::byte>(decoded_.data(), encoded_size / 2);
    }

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept {
        return bytes_;
    }

private:
    static uint8_t nibble(uint8_t value) noexcept {
        if (value >= '0' && value <= '9')
            return static_cast<uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f')
            return static_cast<uint8_t>(value - 'a' + 10);
        if (value >= 'A' && value <= 'F')
            return static_cast<uint8_t>(value - 'A' + 10);
        return 0xff;
    }

    std::array<std::byte, 512> decoded_ {};
    std::span<const std::byte> bytes_;
};

} // namespace shinku::cache::fuzzing
