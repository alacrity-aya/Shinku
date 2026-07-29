// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/cache_candidate.h"
#include "cache/cache_store.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;
using shinku::cache::CacheCandidate;
using shinku::cache::CacheEntryKind;
using shinku::cache::CacheKey;
using shinku::cache::CacheLifetime;
using shinku::cache::CacheNamespace;
using shinku::cache::CacheTime;
using shinku::cache::CanonicalDnsName;
using shinku::cache::CanonicalNameError;

std::vector<std::byte> wire(std::initializer_list<uint8_t> octets) {
    std::vector<std::byte> result;
    result.reserve(octets.size());
    for (uint8_t octet: octets)
        result.push_back(static_cast<std::byte>(octet));
    return result;
}

CanonicalDnsName name(std::initializer_list<uint8_t> octets) {
    auto result = CanonicalDnsName::from_wire(wire(octets));
    REQUIRE(result.has_value());
    return *result;
}

} // namespace

TEST_CASE("CanonicalDnsName normalizes ASCII label case") {
    const auto mixed_case = wire({ 3, 'W', '-', '1', 7, 'E', 'x', 'A', 'm', 'P', 'l', 'E', 0 });
    const auto lowercase = wire({ 3, 'w', '-', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 });

    auto canonical = CanonicalDnsName::from_wire(mixed_case);
    auto expected = CanonicalDnsName::from_wire(lowercase);

    REQUIRE(canonical.has_value());
    REQUIRE(expected.has_value());
    CHECK(*canonical == *expected);
    CHECK(canonical->size() == mixed_case.size());
}

TEST_CASE("CanonicalDnsName accepts root and the 255-byte DNS limit") {
    auto root = CanonicalDnsName::from_wire(wire({ 0 }));
    REQUIRE(root.has_value());
    CHECK(root->size() == 1);

    std::vector<std::byte> maximum;
    for (int label = 0; label < 3; ++label) {
        maximum.push_back(std::byte { 63 });
        maximum.insert(maximum.end(), 63, std::byte { 'a' });
    }
    maximum.push_back(std::byte { 61 });
    maximum.insert(maximum.end(), 61, std::byte { 'b' });
    maximum.push_back(std::byte { 0 });

    REQUIRE(maximum.size() == CanonicalDnsName::kMaxWireSize);
    CHECK(CanonicalDnsName::from_wire(maximum).has_value());

    maximum.insert(maximum.end() - 1, std::byte { 'x' });
    auto too_long = CanonicalDnsName::from_wire(maximum);
    REQUIRE_FALSE(too_long.has_value());
    CHECK(too_long.error() == CanonicalNameError::TooLong);
}

TEST_CASE("CanonicalDnsName rejects compression and malformed termination") {
    auto compressed = CanonicalDnsName::from_wire(wire({ 0xc0, 0x0c }));
    REQUIRE_FALSE(compressed.has_value());
    CHECK(compressed.error() == CanonicalNameError::CompressionPointer);

    auto reserved_label_type = CanonicalDnsName::from_wire(wire({ 0x40 }));
    REQUIRE_FALSE(reserved_label_type.has_value());
    CHECK(reserved_label_type.error() == CanonicalNameError::InvalidLabel);

    auto truncated = CanonicalDnsName::from_wire(wire({ 3, 'w', 'w' }));
    REQUIRE_FALSE(truncated.has_value());
    CHECK(truncated.error() == CanonicalNameError::TruncatedLabel);

    auto unterminated = CanonicalDnsName::from_wire(wire({ 3, 'w', 'w', 'w' }));
    REQUIRE_FALSE(unterminated.has_value());
    CHECK(unterminated.error() == CanonicalNameError::MissingRootLabel);

    auto trailing = CanonicalDnsName::from_wire(wire({ 0, 0 }));
    REQUIRE_FALSE(trailing.has_value());
    CHECK(trailing.error() == CanonicalNameError::TrailingData);
}

TEST_CASE("CacheKey identity includes namespace name type and class") {
    const CacheKey baseline {
        .cache_namespace = CacheNamespace { .destination_ipv4 = 0x0a000001, .destination_port = 53 },
        .question_name = name({ 1, 'a', 0 }),
        .question_type = 1,
        .question_class = 1,
    };

    auto other_namespace_address = baseline;
    other_namespace_address.cache_namespace.destination_ipv4 = 0x0a000002;
    auto other_namespace_port = baseline;
    other_namespace_port.cache_namespace.destination_port = 5353;
    auto other_name = baseline;
    other_name.question_name = name({ 1, 'b', 0 });
    auto other_type = baseline;
    other_type.question_type = 28;
    auto other_class = baseline;
    other_class.question_class = 3;

    CHECK_FALSE(baseline == other_namespace_address);
    CHECK_FALSE(baseline == other_namespace_port);
    CHECK_FALSE(baseline == other_name);
    CHECK_FALSE(baseline == other_type);
    CHECK_FALSE(baseline == other_class);
}

TEST_CASE("CacheCandidate equality compares borrowed span contents") {
    const CacheKey key {
        .cache_namespace = CacheNamespace { .destination_ipv4 = 0x0a000001, .destination_port = 53 },
        .question_name = name({ 1, 'a', 0 }),
        .question_type = 1,
        .question_class = 1,
    };
    auto first_response = wire({ 1, 2, 3 });
    auto second_response = first_response;
    std::array<uint16_t, 2> first_offsets { 4, 12 };
    std::array<uint16_t, 2> second_offsets = first_offsets;
    const CacheCandidate first {
        .key = key,
        .kind = CacheEntryKind::Positive,
        .lifetime = CacheLifetime { 30s },
        .response = first_response,
        .ttl_offsets = first_offsets,
    };
    CacheCandidate second {
        .key = key,
        .kind = CacheEntryKind::Positive,
        .lifetime = CacheLifetime { 30s },
        .response = second_response,
        .ttl_offsets = second_offsets,
    };

    CHECK(first == second);

    second_response.back() = std::byte { 4 };
    CHECK(first != second);
    second_response.back() = std::byte { 3 };
    second_offsets.back() = 13;
    CHECK(first != second);
}

TEST_CASE("CacheTime is strongly separated from standard clock domains") {
    constexpr CacheTime start { 10ns };
    constexpr CacheTime later = start + 2s;

    STATIC_CHECK(later > start);
    STATIC_CHECK(later - start == 2s);
    STATIC_CHECK_FALSE(std::constructible_from<CacheTime, std::chrono::steady_clock::time_point>);
    STATIC_CHECK_FALSE(std::same_as<CacheTime, std::chrono::steady_clock::time_point>);
}

TEST_CASE("Cache Store error names are stable and allocation-free") {
    using shinku::cache::cache_store_error_name;
    using shinku::cache::CacheStoreErrorCode;

    CHECK(cache_store_error_name(CacheStoreErrorCode::StorageUnavailable) == std::string_view("storage unavailable"));
    CHECK(cache_store_error_name(CacheStoreErrorCode::WriteFailed) == std::string_view("write failed"));
    CHECK(cache_store_error_name(CacheStoreErrorCode::CleanupFailed) == std::string_view("cleanup failed"));
}
