// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/wire_parser.h"

#include "cache/canonical_name.h"
#include "cache/dns/parse_error.h"
#include "cache/dns/parsed_response.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>

namespace shinku::cache::dns {
namespace {

constexpr size_t kDnsHeaderSize = 12;
constexpr size_t kQuestionFieldsSize = 4;
constexpr size_t kResourceRecordFieldsSize = 10;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kTypeSoa = 6;
constexpr uint16_t kClassIn = 1;
constexpr uint32_t kTtlHighBit = 0x8000'0000U;

enum class DnsSection : uint8_t {
    Answer,
    Authority,
    Additional,
};

struct EncodedName {
    size_t end_offset;
    bool compressed;
};

uint16_t read_u16(std::span<const std::byte> message, size_t offset) noexcept {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(std::to_integer<uint8_t>(message[offset])) << 8U
        | std::to_integer<uint8_t>(message[offset + 1])
    );
}

uint32_t read_u32(std::span<const std::byte> message, size_t offset) noexcept {
    return static_cast<uint32_t>(
        static_cast<uint32_t>(std::to_integer<uint8_t>(message[offset])) << 24U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(message[offset + 1])) << 16U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(message[offset + 2])) << 8U
        | std::to_integer<uint8_t>(message[offset + 3])
    );
}

std::expected<EncodedName, ParseError> scan_encoded_name(std::span<const std::byte> message, size_t start) noexcept {
    size_t cursor = start;
    while (cursor < message.size()) {
        const auto first = std::to_integer<uint8_t>(message[cursor]);
        const auto label_type = static_cast<uint8_t>(first & 0xc0U);

        if (label_type == 0xc0U) {
            if (message.size() - cursor < 2)
                return std::unexpected(ParseError::NameTruncated);
            cursor += 2;
            if (cursor - start > CanonicalDnsName::kMaxWireSize)
                return std::unexpected(ParseError::NameTooLong);
            return EncodedName { .end_offset = cursor, .compressed = true };
        }
        if (label_type != 0)
            return std::unexpected(ParseError::InvalidLabelType);

        ++cursor;
        if (first == 0) {
            if (cursor - start > CanonicalDnsName::kMaxWireSize)
                return std::unexpected(ParseError::NameTooLong);
            return EncodedName { .end_offset = cursor, .compressed = false };
        }
        if (message.size() - cursor < first)
            return std::unexpected(ParseError::NameTruncated);

        cursor += first;
        if (cursor - start >= CanonicalDnsName::kMaxWireSize)
            return std::unexpected(ParseError::NameTooLong);
    }

    return std::unexpected(ParseError::NameTruncated);
}

ParseError canonical_name_error(CanonicalNameError error) noexcept {
    switch (error) {
        case CanonicalNameError::TooLong:
            return ParseError::NameTooLong;
        case CanonicalNameError::InvalidLabel:
            return ParseError::InvalidLabelType;
        case CanonicalNameError::Empty:
        case CanonicalNameError::CompressionPointer:
        case CanonicalNameError::TruncatedLabel:
        case CanonicalNameError::MissingRootLabel:
        case CanonicalNameError::TrailingData:
            return ParseError::InvalidCanonicalQuestion;
    }
    return ParseError::InvalidCanonicalQuestion;
}

} // namespace

std::expected<ParsedResponse, ParseError>
parse_response(std::span<const std::byte> message, std::span<uint16_t> ttl_offset_scratch) noexcept {
    if (message.size() > kMaxDnsMessageBytes)
        return std::unexpected(ParseError::MessageTooLarge);
    if (message.size() < kDnsHeaderSize)
        return std::unexpected(ParseError::HeaderTruncated);

    const uint16_t flags = read_u16(message, 2);
    const uint16_t question_count = read_u16(message, 4);
    const uint16_t answer_count = read_u16(message, 6);
    const uint16_t authority_count = read_u16(message, 8);
    const uint16_t additional_count = read_u16(message, 10);

    size_t cursor = kDnsHeaderSize;
    std::optional<CanonicalDnsName> question_name;
    uint16_t question_type = 0;
    uint16_t question_class = 0;
    bool question_is_compressed = false;

    for (uint16_t index = 0; index < question_count; ++index) {
        const size_t name_start = cursor;
        auto encoded_name = scan_encoded_name(message, cursor);
        if (!encoded_name)
            return std::unexpected(encoded_name.error());
        cursor = encoded_name->end_offset;

        if (message.size() - cursor < kQuestionFieldsSize)
            return std::unexpected(ParseError::QuestionFieldsTruncated);

        if (index == 0) {
            question_is_compressed = encoded_name->compressed;
            question_type = read_u16(message, cursor);
            question_class = read_u16(message, cursor + 2);
            if (!question_is_compressed) {
                auto canonical = CanonicalDnsName::from_wire(message.subspan(name_start, cursor - name_start));
                if (!canonical)
                    return std::unexpected(canonical_name_error(canonical.error()));
                question_name = *canonical;
            }
        }
        cursor += kQuestionFieldsSize;
    }

    size_t ttl_offset_count = 0;
    std::optional<uint32_t> minimum_ttl;
    bool authority_has_in_soa = false;

    const auto scan_records = [&](uint16_t count, DnsSection section) -> std::expected<void, ParseError> {
        for (uint16_t index = 0; index < count; ++index) {
            auto owner = scan_encoded_name(message, cursor);
            if (!owner)
                return std::unexpected(owner.error());
            cursor = owner->end_offset;

            if (message.size() - cursor < kResourceRecordFieldsSize)
                return std::unexpected(ParseError::ResourceRecordHeaderTruncated);

            const uint16_t type = read_u16(message, cursor);
            const uint16_t rr_class = read_u16(message, cursor + 2);
            const size_t ttl_offset = cursor + 4;
            const uint32_t wire_ttl = read_u32(message, ttl_offset);
            const uint16_t rdata_size = read_u16(message, cursor + 8);
            cursor += kResourceRecordFieldsSize;

            if (message.size() - cursor < rdata_size)
                return std::unexpected(ParseError::ResourceDataTruncated);

            if (type != kTypeOpt) {
                if (ttl_offset_count >= ttl_offset_scratch.size())
                    return std::unexpected(ParseError::TtlOffsetCapacityExceeded);
                if (ttl_offset > std::numeric_limits<uint16_t>::max())
                    return std::unexpected(ParseError::TtlOffsetCapacityExceeded);

                ttl_offset_scratch[ttl_offset_count++] = static_cast<uint16_t>(ttl_offset);
                const uint32_t ttl = (wire_ttl & kTtlHighBit) == 0 ? wire_ttl : 0;
                minimum_ttl = minimum_ttl ? std::min(*minimum_ttl, ttl) : ttl;
            }

            if (section == DnsSection::Authority && type == kTypeSoa && rr_class == kClassIn)
                authority_has_in_soa = true;

            cursor += rdata_size;
        }
        return {};
    };

    if (auto result = scan_records(answer_count, DnsSection::Answer); !result)
        return std::unexpected(result.error());
    if (auto result = scan_records(authority_count, DnsSection::Authority); !result)
        return std::unexpected(result.error());
    if (auto result = scan_records(additional_count, DnsSection::Additional); !result)
        return std::unexpected(result.error());

    return ParsedResponse {
        .message = message,
        .flags = flags,
        .question_count = question_count,
        .answer_count = answer_count,
        .authority_count = authority_count,
        .additional_count = additional_count,
        .question_name = question_name,
        .question_type = question_type,
        .question_class = question_class,
        .question_is_compressed = question_is_compressed,
        .minimum_ttl = minimum_ttl,
        .authority_has_in_soa = authority_has_in_soa,
        .ttl_offsets = ttl_offset_scratch.first(ttl_offset_count),
    };
}

} // namespace shinku::cache::dns
