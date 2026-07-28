// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_time.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace shinku::cache::testing {

enum class CacheHitApplyError : uint8_t {
    TimeBeforeInsertion,
    InvalidTransactionId,
    InvalidQuestionRange,
    InvalidTtlOffset,
};

struct CacheHitInput {
    std::span<const std::byte> response_template;
    std::span<const std::byte> query;
    std::size_t question_offset;
    std::size_t question_size;
    std::span<const uint16_t> ttl_offsets;
    CacheTime stored_at;
    CacheLifetime lifetime;
};

using CacheHitResponse = std::optional<std::vector<std::byte>>;

[[nodiscard]] inline std::expected<CacheHitResponse, CacheHitApplyError>
apply_cache_hit(const CacheHitInput& input, CacheTime hit_at) {
    if (hit_at < input.stored_at)
        return std::unexpected(CacheHitApplyError::TimeBeforeInsertion);
    if (input.response_template.size() < 2 || input.query.size() < 2)
        return std::unexpected(CacheHitApplyError::InvalidTransactionId);
    if (input.question_offset > input.response_template.size()
        || input.question_size > input.response_template.size() - input.question_offset
        || input.question_offset > input.query.size()
        || input.question_size > input.query.size() - input.question_offset)
    {
        return std::unexpected(CacheHitApplyError::InvalidQuestionRange);
    }
    for (uint16_t offset: input.ttl_offsets) {
        if (offset > input.response_template.size() || input.response_template.size() - offset < sizeof(uint32_t))
            return std::unexpected(CacheHitApplyError::InvalidTtlOffset);
    }

    if (hit_at >= input.stored_at + input.lifetime)
        return CacheHitResponse {};

    std::vector<std::byte> response(input.response_template.begin(), input.response_template.end());
    response[0] = input.query[0];
    response[1] = input.query[1];
    std::copy_n(
        input.query.begin() + static_cast<std::ptrdiff_t>(input.question_offset),
        input.question_size,
        response.begin() + static_cast<std::ptrdiff_t>(input.question_offset)
    );

    const auto residence_ns = (hit_at - input.stored_at).count();
    constexpr int64_t kNanosecondsPerSecond = 1'000'000'000;
    for (uint16_t offset: input.ttl_offsets) {
        uint32_t original_ttl = 0;
        for (std::size_t byte = 0; byte < sizeof(uint32_t); ++byte) {
            original_ttl =
                static_cast<uint32_t>((original_ttl << 8U) | std::to_integer<uint8_t>(response[offset + byte]));
        }

        const int64_t remaining_ns = static_cast<int64_t>(original_ttl) * kNanosecondsPerSecond - residence_ns;
        const uint32_t remaining_ttl =
            remaining_ns > 0 ? static_cast<uint32_t>(remaining_ns / kNanosecondsPerSecond) : 0;
        for (std::size_t byte = 0; byte < sizeof(uint32_t); ++byte) {
            const unsigned shift = static_cast<unsigned>((sizeof(uint32_t) - byte - 1) * 8);
            response[offset + byte] = static_cast<std::byte>((remaining_ttl >> shift) & 0xffU);
        }
    }

    return CacheHitResponse(std::move(response));
}

} // namespace shinku::cache::testing
