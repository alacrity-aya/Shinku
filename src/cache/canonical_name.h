// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache {

enum class CanonicalNameError : uint8_t {
    Empty,
    TooLong,
    InvalidLabel,
    CompressionPointer,
    TruncatedLabel,
    MissingRootLabel,
    TrailingData,
};

class CanonicalDnsName {
public:
    static constexpr size_t kMaxWireSize = 255;

    [[nodiscard]] static std::expected<CanonicalDnsName, CanonicalNameError>
    from_wire(std::span<const std::byte> wire) noexcept {
        if (wire.empty())
            return std::unexpected(CanonicalNameError::Empty);
        if (wire.size() > kMaxWireSize)
            return std::unexpected(CanonicalNameError::TooLong);

        CanonicalDnsName result;
        size_t offset = 0;
        while (offset < wire.size()) {
            const auto label_size = std::to_integer<uint8_t>(wire[offset]);
            const auto label_type = static_cast<uint8_t>(label_size & kLabelTypeMask);
            if (label_type == kCompressionPointerType)
                return std::unexpected(CanonicalNameError::CompressionPointer);
            if (label_type != 0)
                return std::unexpected(CanonicalNameError::InvalidLabel);

            result.wire_[offset] = wire[offset];
            ++offset;
            if (label_size == 0) {
                if (offset != wire.size())
                    return std::unexpected(CanonicalNameError::TrailingData);
                result.size_ = static_cast<uint16_t>(offset);
                return result;
            }

            if (label_size > wire.size() - offset)
                return std::unexpected(CanonicalNameError::TruncatedLabel);

            for (size_t i = 0; i < label_size; ++i) {
                auto octet = std::to_integer<uint8_t>(wire[offset + i]);
                if (octet >= 'A' && octet <= 'Z')
                    octet |= kAsciiLowercaseBit;
                result.wire_[offset + i] = static_cast<std::byte>(octet);
            }
            offset += label_size;
        }

        return std::unexpected(CanonicalNameError::MissingRootLabel);
    }

    [[nodiscard]] std::span<const std::byte> wire() const noexcept {
        return { wire_.data(), size_ };
    }

    [[nodiscard]] size_t size() const noexcept {
        return size_;
    }

    friend bool operator==(const CanonicalDnsName& lhs, const CanonicalDnsName& rhs) noexcept {
        return std::ranges::equal(lhs.wire(), rhs.wire());
    }

private:
    static constexpr uint8_t kLabelTypeMask = 0xc0U;
    static constexpr uint8_t kCompressionPointerType = 0xc0U;
    static constexpr uint8_t kAsciiLowercaseBit = 0x20U;

    std::array<std::byte, kMaxWireSize> wire_ {};
    uint16_t size_ = 0;
};

} // namespace shinku::cache
