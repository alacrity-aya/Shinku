// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_store.h"
#include "backend/ebpf/cache/ebpf_cache_map.h"
#include "backend/ebpf/cache/ebpf_cache_secret.h"
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/cache_store_conformance.h"
#include "config/config.h"
#include "ebpf_cache_fingerprint.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace shinku::backend::ebpf {
namespace {

using namespace std::chrono_literals;

class FakeEbpfCacheMap final: public EbpfCacheMap {
public:
    struct Entry {
        ebpf_cache_physical_key key;
        ebpf_cache_publication publication;
    };

    explicit FakeEbpfCacheMap(size_t capacity) {
        entries_.reserve(capacity);
    }

    std::expected<std::optional<ebpf_cache_publication>, std::error_code>
    lookup(const ebpf_cache_physical_key& key) noexcept override {
        if (fail_lookup_) {
            fail_lookup_ = false;
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        const auto found = find(key);
        if (found == entries_.end())
            return std::nullopt;
        return found->publication;
    }

    std::expected<void, std::error_code> update(
        const ebpf_cache_physical_key& key,
        const ebpf_cache_publication& publication,
        EbpfCacheMapUpdateMode mode
    ) noexcept override {
        if (fail_update_) {
            fail_update_ = false;
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        const auto found = find(key);
        if (mode == EbpfCacheMapUpdateMode::Insert) {
            if (found != entries_.end())
                return std::unexpected(std::make_error_code(std::errc::file_exists));
            entries_.push_back({ key, publication });
            return {};
        }
        if (found == entries_.end())
            return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        found->publication = publication;
        return {};
    }

    std::expected<void, std::error_code> erase(const ebpf_cache_physical_key& key) noexcept override {
        if (fail_erase_) {
            fail_erase_ = false;
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        const auto found = find(key);
        if (found == entries_.end())
            return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));
        entries_.erase(found);
        return {};
    }

    void fail_next_update() noexcept {
        fail_update_ = true;
    }
    void fail_next_erase() noexcept {
        fail_erase_ = true;
    }
    void fail_next_lookup() noexcept {
        fail_lookup_ = true;
    }

    [[nodiscard]] const Entry* entry(size_t index) const noexcept {
        return index < entries_.size() ? &entries_[index] : nullptr;
    }

    [[nodiscard]] const Entry* entry(const ebpf_cache_physical_key& key) const noexcept {
        const auto found =
            std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) { return entry.key == key; });
        return found == entries_.end() ? nullptr : &*found;
    }

    [[nodiscard]] size_t size() const noexcept {
        return entries_.size();
    }

private:
    std::vector<Entry>::iterator find(const ebpf_cache_physical_key& key) noexcept {
        return std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) { return entry.key == key; });
    }

    std::vector<Entry> entries_;
    bool fail_lookup_ = false;
    bool fail_update_ = false;
    bool fail_erase_ = false;
};

config::CacheConfig cache_config(uint32_t capacity, uint32_t response_capacity) {
    auto result = config::CacheConfig::create({
        .max_entries = capacity,
        .max_response_bytes = response_capacity,
        .cache_negative = true,
        .max_pending_queries = 16,
        .pending_query_timeout = 1s,
    });
    assert(result.has_value());
    return std::move(*result);
}

cache::CacheKey make_key(uint8_t label) {
    const std::array wire { std::byte { 1 }, static_cast<std::byte>(label), std::byte { 0 } };
    auto name = cache::CanonicalDnsName::from_wire(wire);
    assert(name.has_value());
    return {
        .cache_namespace = { .destination_ipv4 = 0x0a000001, .destination_port = 53 },
        .question_name = *name,
        .question_type = 1,
        .question_class = 1,
    };
}

struct CandidateStorage {
    std::array<std::byte, 32> response {};
    std::array<uint16_t, 1> offsets { 12 };
    std::array<uint16_t, SHINKU_EBPF_CACHE_MAX_TTL_OFFSETS + 1U> oversized_offsets {};

    cache::CacheCandidate candidate(uint8_t key, uint8_t payload, cache::CacheLifetime lifetime = 30s) {
        response.fill(std::byte { 0 });
        response.back() = static_cast<std::byte>(payload);
        return {
            .key = make_key(key),
            .kind = cache::CacheEntryKind::Positive,
            .lifetime = lifetime,
            .response = response,
            .ttl_offsets = offsets,
        };
    }
};

struct StoreHarness {
    explicit StoreHarness(uint32_t capacity = 2, uint32_t response_capacity = 128) {
        auto made_layout = make_ebpf_cache_storage_layout(cache_config(capacity, response_capacity), 4096);
        REQUIRE(made_layout.has_value());
        layout = *made_layout;
        arena.assign(layout.arena_bytes, std::byte { 0xa5 });
        auto fake = std::make_unique<FakeEbpfCacheMap>(capacity);
        map = fake.get();
        auto made_store =
            EbpfCacheStore::create_for_testing(layout, EbpfNativeStorageBinding(0, arena), secret, std::move(fake));
        REQUIRE(made_store.has_value());
        store = std::move(*made_store);
    }

    [[nodiscard]] ebpf_cache_slot_header* header(uint32_t slot_index) {
        return reinterpret_cast<ebpf_cache_slot_header*>(arena.data() + slot_index * layout.slot_stride);
    }

    [[nodiscard]] std::span<const std::byte> response(uint32_t slot_index) {
        const auto* value = header(slot_index);
        return { reinterpret_cast<const std::byte*>(value + 1), value->response_size };
    }

    EbpfCacheStorageLayout layout {};
    ebpf_cache_secret secret { .first = 0x0706050403020100ULL, .second = 0x0f0e0d0c0b0a0908ULL };
    std::vector<std::byte> arena;
    FakeEbpfCacheMap* map = nullptr;
    std::unique_ptr<EbpfCacheStore> store;
};

class EbpfCacheStoreConformanceAdapter final: public cache::testing::CacheStoreConformanceAdapter {
public:
    std::expected<cache::StoreOutcome, cache::CacheStoreError> store(
        uint8_t key,
        uint8_t payload,
        cache::CacheTime now,
        cache::CacheLifetime lifetime,
        bool incomplete_patch_plan = false
    ) noexcept override {
        auto candidate = storage_.candidate(static_cast<uint8_t>('a' + key), payload, lifetime);
        if (reject_next_ || incomplete_patch_plan) {
            storage_.oversized_offsets.fill(12);
            candidate.ttl_offsets = storage_.oversized_offsets;
            reject_next_ = false;
        }
        return harness_.store->store(candidate, now);
    }

    std::expected<cache::CleanupResult, cache::CacheStoreError> cleanup(cache::CacheTime now) noexcept override {
        return harness_.store->cleanup(now);
    }

    bool hit_visible(uint8_t key, cache::CacheTime now) const noexcept override {
        const auto* entry = harness_.map->entry(physical_key(static_cast<uint8_t>('a' + key)));
        if (entry == nullptr)
            return false;
        const auto* header = reinterpret_cast<const ebpf_cache_slot_header*>(
            harness_.arena.data() + (entry->publication.slot_index * harness_.layout.slot_stride)
        );
        return header->generation == entry->publication.generation
            && static_cast<uint64_t>(now.time_since_epoch().count()) < header->expires_at_ns;
    }

    std::optional<uint8_t> payload(uint8_t key) const override {
        const auto* entry = harness_.map->entry(physical_key(static_cast<uint8_t>('a' + key)));
        if (entry == nullptr)
            return std::nullopt;
        const auto* header = reinterpret_cast<const ebpf_cache_slot_header*>(
            harness_.arena.data() + (entry->publication.slot_index * harness_.layout.slot_stride)
        );
        const auto* response = reinterpret_cast<const std::byte*>(header + 1);
        return std::to_integer<uint8_t>(response[header->response_size - 1U]);
    }

    void reject_next() noexcept override {
        reject_next_ = true;
    }
    void fail_next_write() noexcept override {
        harness_.map->fail_next_update();
    }

private:
    [[nodiscard]] ebpf_cache_physical_key physical_key(uint8_t label) const noexcept {
        const cache::CacheKey key = make_key(label);
        const auto name = key.question_name.wire();
        return {
            .destination_ipv4 = htonl(key.cache_namespace.destination_ipv4),
            .destination_port = htons(key.cache_namespace.destination_port),
            .reserved = 0,
            .fingerprint = shinku_ebpf_cache_fingerprint(
                reinterpret_cast<const __u8*>(name.data()),
                static_cast<__u32>(name.size()),
                key.question_type,
                key.question_class,
                &harness_.secret
            ),
        };
    }

    StoreHarness harness_;
    CandidateStorage storage_;
    bool reject_next_ = false;
};

constexpr cache::CacheTime epoch() {
    return cache::CacheTime { std::chrono::nanoseconds::zero() };
}

} // namespace

TEST_CASE("eBPF cache layout derives density and worst-case TTL capacity") {
    auto minimum = make_ebpf_cache_storage_layout(cache_config(10, 128), 4096);
    REQUIRE(minimum.has_value());
    CHECK(minimum->ttl_offset_capacity == 10);
    CHECK(minimum->slot_stride == 184);
    CHECK(minimum->required_arena_bytes == 1840);
    CHECK(minimum->arena_bytes == 4096);
    CHECK(minimum->arena_page_count == 1);

    auto maximum = make_ebpf_cache_storage_layout(cache_config(1, 512), 4096);
    REQUIRE(maximum.has_value());
    CHECK(maximum->ttl_offset_capacity == 45);
    CHECK(maximum->slot_stride == SHINKU_EBPF_CACHE_MAX_SLOT_STRIDE);

    const auto zero_page_size = make_ebpf_cache_storage_layout(cache_config(1, 128), 0);
    REQUIRE_FALSE(zero_page_size);
    CHECK(zero_page_size.error() == std::make_error_code(std::errc::invalid_argument));

    const auto excessive_page_count =
        make_ebpf_cache_storage_layout(cache_config(std::numeric_limits<uint32_t>::max(), 512), 1);
    REQUIRE_FALSE(excessive_page_count);
    CHECK(excessive_page_count.error() == std::make_error_code(std::errc::value_too_large));
}

TEST_CASE("eBPF Cache Store satisfies the reusable Cache Store contract") {
    cache::testing::run_cache_store_conformance([] { return std::make_unique<EbpfCacheStoreConformanceAdapter>(); });
}

TEST_CASE("shared SipHash-2-4-128 matches the reference empty-message vector") {
    shinku_siphash128_state state {};
    const ebpf_cache_secret secret {
        .first = 0x0706050403020100ULL,
        .second = 0x0f0e0d0c0b0a0908ULL,
    };
    shinku_siphash128_init(&state, &secret);
    const auto result = shinku_siphash128_finish(&state);
    CHECK(result.first == 0xe6a825ba047f81a3ULL);
    CHECK(result.second == 0x930255c71472f66dULL);

    shinku_siphash128_init(&state, &secret);
    shinku_siphash128_update_byte(&state, 0);
    const auto one_byte = shinku_siphash128_finish(&state);
    CHECK(one_byte.first == 0x44af996bd8c187daULL);
    CHECK(one_byte.second == 0x45fc229b11597634ULL);
}

TEST_CASE("eBPF cache secret comes from the operating system entropy source") {
    CHECK(make_ebpf_cache_secret().has_value());
}

TEST_CASE("eBPF cache Store writes only the active slot region") {
    StoreHarness harness;
    CandidateStorage storage;
    auto candidate = storage.candidate('a', 42);
    REQUIRE(harness.store->store(candidate, epoch()) == cache::StoreOutcome::Inserted);

    REQUIRE(harness.map->size() == 1);
    const auto* published = harness.map->entry(0);
    REQUIRE(published != nullptr);
    const auto* header = harness.header(published->publication.slot_index);
    CHECK((header->sequence & 1U) == 0);
    CHECK(header->response_size == candidate.response.size());
    CHECK(header->ttl_offset_count == 1);
    CHECK(header->generation == published->publication.generation);
    CHECK(header->stored_at_ns == 0);
    CHECK(header->expires_at_ns == 30'000'000'000ULL);
    CHECK(harness.response(published->publication.slot_index).back() == std::byte { 42 });

    const size_t active = ebpf_cache_active_slot_size(candidate.response.size(), candidate.ttl_offsets.size());
    const size_t slot_begin = published->publication.slot_index * harness.layout.slot_stride;
    CHECK(harness.arena[slot_begin + active] == std::byte { 0xa5 });
}

TEST_CASE("same-key publication failure restores the previous slot") {
    StoreHarness harness;
    CandidateStorage storage;
    auto first = storage.candidate('a', 10);
    REQUIRE(harness.store->store(first, epoch()) == cache::StoreOutcome::Inserted);
    const auto old_publication = harness.map->entry(0)->publication;
    const auto old_header = *harness.header(old_publication.slot_index);
    const std::vector old_response(
        harness.response(old_publication.slot_index).begin(),
        harness.response(old_publication.slot_index).end()
    );

    auto second = storage.candidate('a', 20);
    harness.map->fail_next_update();
    const auto result = harness.store->store(second, epoch() + 1s);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().code == cache::CacheStoreErrorCode::WriteFailed);

    REQUIRE(harness.map->entry(0) != nullptr);
    CHECK(harness.map->entry(0)->publication.generation == old_publication.generation);
    const auto* restored = harness.header(old_publication.slot_index);
    CHECK(restored->generation == old_header.generation);
    CHECK(restored->stored_at_ns == old_header.stored_at_ns);
    CHECK(restored->expires_at_ns == old_header.expires_at_ns);
    CHECK(std::ranges::equal(harness.response(old_publication.slot_index), old_response));
}

TEST_CASE("failed insertion remains hidden and returns its slot to the free list") {
    StoreHarness harness(1);
    CandidateStorage storage;
    harness.map->fail_next_update();
    auto failed = harness.store->store(storage.candidate('a', 1), epoch());
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().code == cache::CacheStoreErrorCode::WriteFailed);
    CHECK(harness.map->size() == 0);

    REQUIRE(harness.store->store(storage.candidate('b', 2), epoch()) == cache::StoreOutcome::Inserted);
    REQUIRE(harness.map->entry(0) != nullptr);
    CHECK(harness.map->entry(0)->publication.slot_index == 0);
}

TEST_CASE("failed victim invalidation preserves the published victim") {
    StoreHarness harness(1);
    CandidateStorage storage;
    REQUIRE(harness.store->store(storage.candidate('a', 1), epoch()) == cache::StoreOutcome::Inserted);
    const auto victim = harness.map->entry(0)->publication;

    harness.map->fail_next_erase();
    auto failed = harness.store->store(storage.candidate('b', 2), epoch());
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().code == cache::CacheStoreErrorCode::WriteFailed);
    REQUIRE(harness.map->size() == 1);
    CHECK(harness.map->entry(0)->publication.generation == victim.generation);
    CHECK(harness.response(victim.slot_index).back() == std::byte { 1 });
}

TEST_CASE("map lookup failure is reported as unavailable storage") {
    StoreHarness harness;
    CandidateStorage storage;
    harness.map->fail_next_lookup();
    auto failed = harness.store->store(storage.candidate('a', 1), epoch());
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().code == cache::CacheStoreErrorCode::StorageUnavailable);
}

TEST_CASE("eBPF cache Store replaces round-robin and reuses cleanup slots") {
    StoreHarness harness;
    CandidateStorage storage;
    REQUIRE(harness.store->store(storage.candidate('a', 1, 1s), epoch()) == cache::StoreOutcome::Inserted);
    REQUIRE(harness.store->store(storage.candidate('b', 2), epoch()) == cache::StoreOutcome::Inserted);
    REQUIRE(harness.store->store(storage.candidate('c', 3), epoch() + 1s) == cache::StoreOutcome::Inserted);
    CHECK(harness.map->size() == 2);

    auto cleanup = harness.store->cleanup(epoch() + 31s);
    REQUIRE(cleanup.has_value());
    CHECK(cleanup->removed_entries == 2);
    CHECK_FALSE(cleanup->more_work);
    CHECK(harness.map->size() == 0);

    REQUIRE(harness.store->store(storage.candidate('d', 4), epoch() + 31s) == cache::StoreOutcome::Inserted);
    REQUIRE(harness.map->entry(0) != nullptr);
    CHECK(harness.map->entry(0)->publication.slot_index < 2);
}

TEST_CASE("eBPF cache cleanup bounds one capacity sweep") {
    StoreHarness harness(300);
    CandidateStorage storage;
    REQUIRE(harness.store->store(storage.candidate('a', 1, 1s), epoch()) == cache::StoreOutcome::Inserted);

    auto first = harness.store->cleanup(epoch() + 1s);
    REQUIRE(first.has_value());
    CHECK(first->removed_entries == 1);
    CHECK(first->more_work);

    auto second = harness.store->cleanup(epoch() + 1s);
    REQUIRE(second.has_value());
    CHECK(second->removed_entries == 0);
    CHECK_FALSE(second->more_work);
}

TEST_CASE("cleanup leaves ownership intact when map deletion fails") {
    StoreHarness harness(1);
    CandidateStorage storage;
    REQUIRE(harness.store->store(storage.candidate('a', 1, 1s), epoch()) == cache::StoreOutcome::Inserted);
    harness.map->fail_next_erase();

    auto failed = harness.store->cleanup(epoch() + 1s);
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().code == cache::CacheStoreErrorCode::CleanupFailed);
    CHECK(harness.map->size() == 1);

    auto retried = harness.store->cleanup(epoch() + 1s);
    REQUIRE(retried.has_value());
    CHECK(retried->removed_entries == 1);
    CHECK(harness.map->size() == 0);
}

TEST_CASE("Store and cleanup serialize concurrent Host writers") {
    StoreHarness harness;
    CandidateStorage expiring_storage;
    CandidateStorage new_storage;
    REQUIRE(harness.store->store(expiring_storage.candidate('a', 1, 1s), epoch()) == cache::StoreOutcome::Inserted);

    std::expected<cache::StoreOutcome, cache::CacheStoreError> stored = cache::StoreOutcome::Rejected;
    std::expected<cache::CleanupResult, cache::CacheStoreError> cleaned = cache::CleanupResult {};
    auto new_candidate = new_storage.candidate('b', 2);
    std::jthread writer([&] { stored = harness.store->store(new_candidate, epoch() + 2s); });
    std::jthread cleaner([&] { cleaned = harness.store->cleanup(epoch() + 2s); });
    writer.join();
    cleaner.join();

    CHECK(stored.has_value());
    CHECK(cleaned.has_value());
    CHECK(harness.map->size() == 1);
}

TEST_CASE("eBPF cache Store rejects a TTL patch plan exceeding layout capacity") {
    StoreHarness harness;
    CandidateStorage storage;
    auto candidate = storage.candidate('a', 1);
    storage.oversized_offsets.fill(12);
    candidate.ttl_offsets = storage.oversized_offsets;
    CHECK(harness.store->store(candidate, epoch()) == cache::StoreOutcome::Rejected);
    CHECK(harness.map->size() == 0);
}

TEST_CASE("eBPF cache Store rejects unrepresentable expiry timestamps") {
    StoreHarness harness;
    CandidateStorage storage;

    auto unrepresentable = storage.candidate('a', 1, cache::CacheLifetime { 10'000'000'000LL });
    const cache::CacheTime late_time { cache::CacheTime::duration::max() };
    CHECK(harness.store->store(unrepresentable, late_time) == cache::StoreOutcome::Rejected);
    CHECK(harness.map->size() == 0);

    auto valid = storage.candidate('b', 2);
    CHECK(harness.store->store(valid, epoch()) == cache::StoreOutcome::Inserted);
    CHECK(harness.map->size() == 1);
}

} // namespace shinku::backend::ebpf
