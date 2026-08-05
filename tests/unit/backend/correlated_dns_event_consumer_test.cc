// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/correlated_dns_event_consumer.h"

#include "../cache/dns_test_message.h"
#include "cache/cache_candidate.h"
#include "cache/cache_store_error.h"
#include "ebpf_cache_abi.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <vector>

namespace {

using namespace std::chrono_literals;
using shinku::backend::ebpf::CorrelatedDnsEventConsumer;
using shinku::cache::CacheCandidate;
using shinku::cache::CacheKey;
using shinku::cache::CacheStore;
using shinku::cache::CacheStoreError;
using shinku::cache::CacheStoreErrorCode;
using shinku::cache::CacheTime;
using shinku::cache::CleanupResult;
using shinku::cache::DnsPolicy;
using shinku::cache::StoreOutcome;
using namespace shinku::cache::test;

CacheTime current_time;

CacheTime test_time_source() noexcept {
    return current_time;
}

class RecordingStore final: public CacheStore {
public:
    std::expected<StoreOutcome, CacheStoreError>
    store(const CacheCandidate& candidate, CacheTime observed_at, CacheTime now) noexcept override {
        ++store_calls;
        key = candidate.key;
        response.assign(candidate.response.begin(), candidate.response.end());
        ttl_offsets.assign(candidate.ttl_offsets.begin(), candidate.ttl_offsets.end());
        observation_time = observed_at;
        admission_time = now;
        if (fail_next) {
            fail_next = false;
            return std::unexpected(CacheStoreError {
                .code = CacheStoreErrorCode::WriteFailed,
                .cause = std::nullopt,
            });
        }
        return StoreOutcome::Inserted;
    }

    std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime) noexcept override {
        return CleanupResult {};
    }

    size_t store_calls = 0;
    bool fail_next = false;
    std::optional<CacheKey> key;
    std::vector<std::byte> response;
    std::vector<uint16_t> ttl_offsets;
    CacheTime observation_time {};
    CacheTime admission_time {};
};

Message cacheable_response() {
    auto message = recursive_response(1);
    const auto owner = pointer_owner();
    const auto address = ipv4_rdata(42);
    append_record(message, owner, 1, 1, 90, address);
    return message;
}

std::array<std::byte, SHINKU_EBPF_CORRELATED_EVENT_BYTES>
event_for(std::span<const std::byte> response, std::byte poison = std::byte { 0xa5 }) {
    std::array<std::byte, SHINKU_EBPF_CORRELATED_EVENT_BYTES> event;
    event.fill(poison);
    const uint64_t observed_at = 10'000'000'000ULL;
    const __be32 destination_ipv4 = htonl(0xc000'0235U);
    const __be16 destination_port = htons(53);
    const __be16 response_size = htons(static_cast<uint16_t>(response.size()));
    std::memcpy(event.data(), &observed_at, sizeof(observed_at));
    std::memcpy(
        event.data() + offsetof(ebpf_correlated_dns_event, destination_ipv4),
        &destination_ipv4,
        sizeof(destination_ipv4)
    );
    std::memcpy(
        event.data() + offsetof(ebpf_correlated_dns_event, destination_port),
        &destination_port,
        sizeof(destination_port)
    );
    std::memcpy(
        event.data() + offsetof(ebpf_correlated_dns_event, response_size),
        &response_size,
        sizeof(response_size)
    );
    std::memcpy(event.data() + offsetof(ebpf_correlated_dns_event, response), response.data(), response.size());
    return event;
}

} // namespace

TEST_CASE("Correlated DNS event consumer decodes the active event prefix") {
    const auto message = cacheable_response();
    const auto event = event_for(message);
    current_time = CacheTime(11s);
    DnsPolicy policy(512, true);
    RecordingStore store;
    CorrelatedDnsEventConsumer consumer(policy, store, test_time_source);

    std::array<std::byte, SHINKU_EBPF_CORRELATED_EVENT_BYTES + 1> unaligned {};
    std::memcpy(unaligned.data() + 1, event.data(), event.size());
    consumer.consume(std::span(unaligned).subspan(1));

    REQUIRE(store.store_calls == 1);
    REQUIRE(store.key.has_value());
    CHECK(store.key->cache_namespace.destination_ipv4 == 0xc000'0235U);
    CHECK(store.key->cache_namespace.destination_port == 53);
    CHECK(store.observation_time == CacheTime(10s));
    CHECK(store.admission_time == CacheTime(11s));
    CHECK(store.response == message);
    CHECK(store.ttl_offsets == std::vector<uint16_t> { 35 });
}

TEST_CASE("Correlated DNS event consumer ignores the inactive event suffix") {
    const auto message = cacheable_response();
    const auto first_event = event_for(message, std::byte { 0x11 });
    const auto second_event = event_for(message, std::byte { 0xee });
    current_time = CacheTime(11s);
    DnsPolicy first_policy(512, true);
    DnsPolicy second_policy(512, true);
    RecordingStore first_store;
    RecordingStore second_store;
    CorrelatedDnsEventConsumer first(first_policy, first_store, test_time_source);
    CorrelatedDnsEventConsumer second(second_policy, second_store, test_time_source);

    first.consume(first_event);
    second.consume(second_event);

    REQUIRE(first_store.store_calls == 1);
    REQUIRE(second_store.store_calls == 1);
    CHECK(first_store.key == second_store.key);
    CHECK(first_store.response == second_store.response);
    CHECK(first_store.ttl_offsets == second_store.ttl_offsets);
    CHECK(first_store.observation_time == second_store.observation_time);
}

TEST_CASE("Correlated DNS event failures remain local to each sample") {
    const auto message = cacheable_response();
    auto event = event_for(message);
    current_time = CacheTime(11s);
    DnsPolicy policy(512, true);
    RecordingStore store;
    CorrelatedDnsEventConsumer consumer(policy, store, test_time_source);

    consumer.consume(std::span(event).first(event.size() - 1));
    CHECK(store.store_calls == 0);

    const __be16 too_short = htons(11);
    std::memcpy(event.data() + offsetof(ebpf_correlated_dns_event, response_size), &too_short, sizeof(too_short));
    consumer.consume(event);
    CHECK(store.store_calls == 0);

    event = event_for(message);
    store.fail_next = true;
    consumer.consume(event);
    consumer.consume(event);
    CHECK(store.store_calls == 2);
}
