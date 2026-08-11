// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache/dns/response_policy.h"

#include "cache/bypass_reason.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/dns/parsed_response.h"
#include "dns_test_message.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace {

using namespace std::chrono_literals;
using shinku::cache::BypassReason;
using shinku::cache::CacheEntryKind;
using shinku::cache::CacheNamespace;
using shinku::cache::CanonicalDnsName;
using shinku::cache::dns::judge_response;
using shinku::cache::dns::ParsedResponse;
using namespace shinku::cache::test;

constexpr CacheNamespace kNamespace { .destination_ipv4 = 0x0a00'0001U, .destination_port = 53 };

struct PolicyFixture {
    Message message { std::byte { 0 } };
    std::array<uint16_t, 1> offsets { 20 };
    CanonicalDnsName name = *CanonicalDnsName::from_wire(wire_name("www.example"));
    ParsedResponse response {
        .message = message,
        .flags = 0x8180,
        .question_count = 1,
        .additional_count = 0,
        .question_name = name,
        .question_type = 1,
        .question_class = 1,
        .minimum_ttl = 30,
        .authority_has_in_soa = false,
        .ttl_offsets = offsets,
    };
};

} // namespace

TEST_CASE("response policy constructs positive identity and lifetime") {
    PolicyFixture fixture;
    auto candidate = judge_response(fixture.response, kNamespace, true);

    REQUIRE(candidate.has_value());
    CHECK(candidate->kind == CacheEntryKind::Positive);
    CHECK(candidate->lifetime == 30s);
    CHECK(candidate->key.cache_namespace == kNamespace);
    CHECK(candidate->key.question_name == fixture.name);
    CHECK(candidate->response.data() == fixture.message.data());
    CHECK(candidate->ttl_offsets.data() == fixture.offsets.data());
}

TEST_CASE("response policy permits verbatim AA RA and AD response flags") {
    PolicyFixture fixture;
    fixture.response.flags = 0x85a0;

    auto candidate = judge_response(fixture.response, kNamespace, true);

    REQUIRE(candidate.has_value());
    CHECK(candidate->kind == CacheEntryKind::Positive);
}

TEST_CASE("response policy classifies packet-cache negative kinds") {
    PolicyFixture fixture;

    SECTION("NXDOMAIN comes from RCODE") {
        fixture.response.flags = 0x8183;
        auto candidate = judge_response(fixture.response, kNamespace, true);
        REQUIRE(candidate.has_value());
        CHECK(candidate->kind == CacheEntryKind::NxDomain);
    }

    SECTION("NOERROR with Authority IN SOA is NoData") {
        fixture.response.authority_has_in_soa = true;
        auto candidate = judge_response(fixture.response, kNamespace, true);
        REQUIRE(candidate.has_value());
        CHECK(candidate->kind == CacheEntryKind::NoData);
    }

    SECTION("negative caching switch bypasses both kinds") {
        fixture.response.flags = 0x8183;
        auto candidate = judge_response(fixture.response, kNamespace, false);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::NegativeCachingDisabled);
    }
}

TEST_CASE("response policy enforces the correlated Response Profile") {
    PolicyFixture fixture;

    struct Case {
        uint16_t flags;
        uint16_t questions;
        uint16_t additional;
        uint16_t type;
        uint16_t rr_class;
        bool compressed;
        BypassReason expected;
    };

    const std::array cases {
        Case { 0x0180, 1, 0, 1, 1, false, BypassReason::NotAResponse },
        Case { 0x8980, 1, 0, 1, 1, false, BypassReason::UnsupportedOpcode },
        Case { 0x8180, 0, 0, 1, 1, false, BypassReason::QuestionCountMismatch },
        Case { 0x8380, 1, 0, 1, 1, false, BypassReason::TruncatedResponse },
        Case { 0x8180, 1, 1, 1, 1, false, BypassReason::AdditionalSectionPresent },
        Case { 0x8080, 1, 0, 1, 1, false, BypassReason::RecursionNotDesired },
        Case { 0x8190, 1, 0, 1, 1, false, BypassReason::CheckingDisabled },
        Case { 0x81c0, 1, 0, 1, 1, false, BypassReason::ReservedFlagSet },
        Case { 0x8180, 1, 0, 1, 1, true, BypassReason::UnsupportedQuestionEncoding },
        Case { 0x8180, 1, 0, 28, 1, false, BypassReason::UnsupportedQuestionType },
        Case { 0x8180, 1, 0, 1, 3, false, BypassReason::UnsupportedQuestionClass },
        Case { 0x8182, 1, 0, 1, 1, false, BypassReason::UnsupportedRcode },
    };

    for (const auto& test_case: cases) {
        fixture.response.flags = test_case.flags;
        fixture.response.question_count = test_case.questions;
        fixture.response.additional_count = test_case.additional;
        fixture.response.question_type = test_case.type;
        fixture.response.question_class = test_case.rr_class;
        fixture.response.question_name = test_case.compressed ? std::nullopt : std::optional { fixture.name };

        auto candidate = judge_response(fixture.response, kNamespace, true);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == test_case.expected);
    }
}

TEST_CASE("response policy requires a positive whole-template lifetime") {
    PolicyFixture fixture;

    SECTION("no RR TTL") {
        fixture.response.minimum_ttl = std::nullopt;
        auto candidate = judge_response(fixture.response, kNamespace, true);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::NoResourceRecordTtl);
    }

    SECTION("zero TTL") {
        fixture.response.minimum_ttl = 0;
        auto candidate = judge_response(fixture.response, kNamespace, true);
        REQUIRE_FALSE(candidate.has_value());
        CHECK(candidate.error() == BypassReason::ZeroLifetime);
    }
}
