// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace shinku::cache {

/// Failure modes when constructing a @ref CanonicalDnsName from wire bytes.
enum class CanonicalNameError : uint8_t {
    Empty, ///< The input contained no bytes at all.
    TooLong, ///< The input exceeded @ref CanonicalDnsName::kMaxWireSize bytes.
    InvalidLabel, ///< A label used an unsupported length or type byte.
    CompressionPointer, ///< A name referenced a compression pointer, which is never stored.
    TruncatedLabel, ///< A label length exceeded the remaining input.
    MissingRootLabel, ///< The input ended without a terminating zero-length root label.
    TrailingData, ///< Extra bytes followed the terminating root label.
};

/**
 * @brief Canonical, case-normalized DNS name held in wire format.
 *
 * Stores a single DNS name in RFC 1035 wire form (length-prefixed labels
 * terminated by a zero-length root label) with all uppercase ASCII letters
 * folded to lowercase, so that names differing only by case compare equal.
 * Compression pointers are rejected so every stored name is fully expanded
 * and self-contained, which keeps cache lookup keys total over the wire bytes.
 */
class CanonicalDnsName {
public:
    /// Maximum number of wire-format bytes a DNS name may occupy (RFC 1035 §3.1).
    static constexpr size_t kMaxWireSize = 255;

    /**
     * @brief Build a canonical name from raw DNS wire bytes.
     *
     * The input must be a fully-expanded (no compression pointers) wire name
     * ending in a zero-length root label. Letters `A`-`Z` are folded to
     * lowercase in place during construction.
     *
     * @param wire Raw wire bytes of the name to canonicalize.
     * @return The canonical name, or a @ref CanonicalNameError describing why
     *         the input was rejected.
     */
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

    /// @return A read-only view of the canonical wire bytes.
    [[nodiscard]] std::span<const std::byte> wire() const noexcept {
        return { wire_.data(), size_ };
    }

    /// @return The number of wire bytes occupied by this name.
    [[nodiscard]] size_t size() const noexcept {
        return size_;
    }

    /// @brief Compares two names by their canonical wire bytes.
    friend bool operator==(const CanonicalDnsName& lhs, const CanonicalDnsName& rhs) noexcept {
        return std::ranges::equal(lhs.wire(), rhs.wire());
    }

private:
    static constexpr uint8_t kLabelTypeMask = 0xc0U; ///< Mask isolating the label-type bits.
    static constexpr uint8_t kCompressionPointerType = 0xc0U; ///< Bits indicating a compression pointer label.
    static constexpr uint8_t kAsciiLowercaseBit = 0x20U; ///< Bit to fold ASCII uppercase to lowercase.

    std::array<std::byte, kMaxWireSize> wire_ {}; ///< Backing storage for the canonical wire bytes.
    uint16_t size_ = 0; ///< Number of valid bytes in @ref wire_.
};

} // namespace shinku::cache
