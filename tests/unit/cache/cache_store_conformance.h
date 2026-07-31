// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "cache/cache_store.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <thread>

namespace shinku::cache::testing {

class CacheStoreConformanceAdapter {
public:
    virtual ~CacheStoreConformanceAdapter() = default;

    virtual std::expected<StoreOutcome, CacheStoreError> store(
        uint8_t key,
        uint8_t payload,
        CacheTime now,
        CacheLifetime lifetime,
        bool incomplete_patch_plan = false
    ) noexcept = 0;
    virtual std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime now) noexcept = 0;
    virtual bool hit_visible(uint8_t key, CacheTime now) const noexcept = 0;
    virtual std::optional<uint8_t> payload(uint8_t key) const = 0;
    virtual void reject_next() noexcept = 0;
    virtual void fail_next_write() noexcept = 0;
};

template<typename Factory>
void run_cache_store_conformance(Factory&& make_adapter) {
    using namespace std::chrono_literals;
    const CacheTime epoch { std::chrono::nanoseconds::zero() };

    SECTION("reports Inserted and Rejected outcomes") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 30s) == StoreOutcome::Inserted);
        adapter->reject_next();
        REQUIRE(adapter->store(2, 20, epoch, 30s) == StoreOutcome::Rejected);
    }

    SECTION("Updated publishes the new payload and refreshes expiry") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 10s) == StoreOutcome::Inserted);
        REQUIRE(adapter->store(1, 11, epoch + 1s, 30s) == StoreOutcome::Updated);

        CHECK(adapter->payload(1) == 11);
        CHECK(adapter->hit_visible(1, epoch + 10s));
        CHECK(adapter->hit_visible(1, epoch + 30s));
        CHECK_FALSE(adapter->hit_visible(1, epoch + 31s));
    }

    SECTION("Replaced publishes the candidate and displaces exactly one live key") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 30s) == StoreOutcome::Inserted);
        REQUIRE(adapter->store(2, 20, epoch, 30s) == StoreOutcome::Inserted);
        REQUIRE(adapter->hit_visible(1, epoch + 1s));
        REQUIRE(adapter->hit_visible(2, epoch + 1s));

        REQUIRE(adapter->store(3, 30, epoch + 1s, 30s) == StoreOutcome::Replaced);
        CHECK(adapter->hit_visible(3, epoch + 1s));
        CHECK(adapter->payload(3) == 30);

        const bool first_survives = adapter->hit_visible(1, epoch + 1s);
        const bool second_survives = adapter->hit_visible(2, epoch + 1s);
        CHECK(first_survives != second_survives);
    }

    SECTION("reusing expired storage is Inserted") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 1s) == StoreOutcome::Inserted);
        REQUIRE(adapter->store(2, 20, epoch, 1s) == StoreOutcome::Inserted);
        REQUIRE(adapter->store(3, 30, epoch + 1s, 30s) == StoreOutcome::Inserted);
    }

    SECTION("Rejected preserves published entries and does not retain candidate spans") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 30s) == StoreOutcome::Inserted);
        const auto before = adapter->payload(1);

        adapter->reject_next();
        REQUIRE(adapter->store(2, 20, epoch, 30s) == StoreOutcome::Rejected);
        CHECK(adapter->hit_visible(1, epoch));
        CHECK(adapter->hit_visible(1, epoch + 29s));
        CHECK_FALSE(adapter->hit_visible(1, epoch + 30s));
        CHECK(adapter->payload(1) == before);
        CHECK_FALSE(adapter->hit_visible(2, epoch));
    }

    SECTION("WriteFailed never publishes the candidate") {
        auto adapter = make_adapter();
        adapter->fail_next_write();
        auto result = adapter->store(1, 10, epoch, 30s);

        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == CacheStoreErrorCode::WriteFailed);
        CHECK_FALSE(adapter->hit_visible(1, epoch));
    }

    SECTION("an incomplete TTL patch plan is rejected rather than truncated") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 30s, true) == StoreOutcome::Rejected);
        CHECK_FALSE(adapter->hit_visible(1, epoch));
    }

    SECTION("cleanup is bounded and reports remaining work") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 1s) == StoreOutcome::Inserted);
        REQUIRE(adapter->store(2, 20, epoch, 1s) == StoreOutcome::Inserted);

        size_t removed = 0;
        bool more_work = false;
        do {
            auto result = adapter->cleanup(epoch + 1s);
            REQUIRE(result.has_value());
            removed += result->removed_entries;
            more_work = result->more_work;
        } while (more_work);
        CHECK(removed == 2);
    }

    SECTION("one store caller may run concurrently with cleanup") {
        auto adapter = make_adapter();
        REQUIRE(adapter->store(1, 10, epoch, 1s) == StoreOutcome::Inserted);
        std::atomic_bool stored = false;
        std::atomic_bool cleaned = false;

        std::jthread writer([&] { stored = adapter->store(2, 20, epoch + 2s, 30s).has_value(); });
        std::jthread cleaner([&] { cleaned = adapter->cleanup(epoch + 2s).has_value(); });
        writer.join();
        cleaner.join();

        CHECK(stored.load());
        CHECK(cleaned.load());
        CHECK(adapter->hit_visible(2, epoch + 2s));
    }
}

} // namespace shinku::cache::testing
