// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns_policy.h"

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "dns_test_message.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace {

using namespace std::chrono_literals;
using shinku::cache::BypassReason;
using shinku::cache::CacheEntryKind;
using shinku::cache::CacheNamespace;
using shinku::cache::DnsPolicy;
using namespace shinku::cache::test;

constexpr CacheNamespace kNamespace { .destination_ipv4 = 0x7f00'0035U, .destination_port = 53 };

} // namespace

TEST_CASE("DnsPolicy classifies a real positive Response") {
    auto message = recursive_response(1);
    const auto owner = pointer_owner();
    const auto address = ipv4_rdata(10);
    append_record(message, owner, 1, 1, 90, address);
    DnsPolicy policy(512, true);

    auto candidate = policy.classify_response(message, kNamespace);

    REQUIRE(candidate.has_value());
    CHECK(candidate->kind == CacheEntryKind::Positive);
    CHECK(candidate->lifetime == 90s);
    CHECK(candidate->key.cache_namespace == kNamespace);
    CHECK(std::ranges::equal(candidate->key.question_name.wire(), wire_name("www.example")));
    CHECK(candidate->response.data() == message.data());
    REQUIRE(candidate->ttl_offsets.size() == 1);
    CHECK(candidate->ttl_offsets[0] == 35);
}

TEST_CASE("DnsPolicy admits structurally valid opaque Answer semantics") {
    auto message = recursive_response(1);
    const auto unrelated_owner = wire_name("unrelated.example");
    const auto address = ipv4_rdata();
    append_record(message, unrelated_owner, 1, 1, 30, address);
    DnsPolicy policy(512, true);

    auto candidate = policy.classify_response(message, kNamespace);

    REQUIRE(candidate.has_value());
    CHECK(candidate->kind == CacheEntryKind::Positive);
    CHECK(std::ranges::equal(candidate->key.question_name.wire(), wire_name("www.example")));
}

TEST_CASE("DnsPolicy classifies negative responses from bounded packet facts") {
    const auto owner = pointer_owner();

    SECTION("NXDOMAIN") {
        auto message = header(0x8183, 1, 0, 1, 0);
        const auto question = wire_name("missing.example");
        append_question(message, question, 1, 1);
        append_record(message, owner, 6, 1, 45, {});
        DnsPolicy policy(512, true);

        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE(candidate.has_value());
        CHECK(candidate->kind == CacheEntryKind::NxDomain);
        CHECK(candidate->lifetime == 45s);
    }

    SECTION("NODATA") {
        auto message = recursive_response(0, 1);
        append_record(message, owner, 6, 1, 45, {});
        DnsPolicy policy(512, true);

        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE(candidate.has_value());
        CHECK(candidate->kind == CacheEntryKind::NoData);
    }
}

TEST_CASE("DnsPolicy maps structural failures and policy bypasses separately") {
    SECTION("malformed") {
        Message message(11);
        DnsPolicy policy(512, true);
        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::MalformedResponse);
    }

    SECTION("oversize is checked before parsing") {
        Message message(129);
        DnsPolicy policy(128, true);
        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::ResponseTooLarge);
    }

    SECTION("compressed Question") {
        auto message = header(0x8180, 1, 0, 0, 0);
        const auto compressed = pointer_owner();
        append_question(message, compressed, 1, 1);
        DnsPolicy policy(512, true);
        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::UnsupportedQuestionEncoding);
    }

    SECTION("Additional Section") {
        auto message = recursive_response(0, 0, 1);
        const auto root = wire_name(".");
        append_record(message, root, 41, 1232, 0, {});
        DnsPolicy policy(512, true);
        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::AdditionalSectionPresent);
    }

    SECTION("TTL high bit") {
        auto message = recursive_response(1);
        const auto owner = pointer_owner();
        const auto address = ipv4_rdata();
        append_record(message, owner, 1, 1, 0x8000'0001U, address);
        DnsPolicy policy(512, true);
        auto candidate = policy.classify_response(message, kNamespace);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::ZeroLifetime);
    }
}

TEST_CASE("Bypass reason names are stable") {
    using shinku::cache::bypass_reason_name;
    CHECK(bypass_reason_name(BypassReason::MalformedResponse) == "malformed response");
    CHECK(bypass_reason_name(BypassReason::ZeroLifetime) == "zero lifetime");
}
