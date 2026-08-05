// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/pending_query_cleaner.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace shinku::backend::ebpf {
namespace {

using namespace std::chrono_literals;

ebpf_pending_query_key key(uint32_t value) {
    return {
        .source_ipv4 = value,
        .destination_ipv4 = value + 1,
        .source_port = static_cast<__be16>(value),
        .destination_port = 53,
        .transaction_id = static_cast<__be16>(value),
        .reserved = 0,
    };
}

ebpf_pending_query_value value(uint64_t last_seen_ns, bool claimed = false) {
    return {
        .fingerprint = { .first = last_seen_ns, .second = last_seen_ns + 1 },
        .state_and_last_seen_ns = last_seen_ns | (claimed ? SHINKU_EBPF_PENDING_CLAIMED : 0),
    };
}

cache::CacheTime at(uint64_t nanoseconds) {
    return cache::CacheTime(std::chrono::nanoseconds(nanoseconds));
}

class FakePendingMap final: public EbpfPendingQueryMap {
public:
    struct Entry {
        ebpf_pending_query_key key;
        ebpf_pending_query_value value;
        bool present = true;
    };

    std::expected<EbpfPendingBatchResult, std::error_code> lookup_batch(
        const ebpf_pending_query_key* input_cursor,
        ebpf_pending_query_key& output_cursor,
        std::span<ebpf_pending_query_key> keys,
        std::span<ebpf_pending_query_value> values
    ) noexcept override {
        if (fail_batch) {
            fail_batch = false;
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        const size_t start = input_cursor == nullptr ? 0 : input_cursor->source_ipv4;
        const size_t remaining = start < entries.size() ? entries.size() - start : 0;
        const size_t count = std::min(remaining, keys.size());
        for (size_t index = 0; index < count; ++index) {
            keys[index] = entries[start + index].key;
            values[index] = entries[start + index].value;
        }
        output_cursor = {};
        output_cursor.source_ipv4 = static_cast<__be32>(start + count);
        return EbpfPendingBatchResult { .count = count, .terminal = start + count >= entries.size() };
    }

    std::expected<std::optional<ebpf_pending_query_value>, std::error_code> lookup(const ebpf_pending_query_key& wanted
    ) noexcept override {
        auto found = find(wanted);
        if (found == entries.end() || !found->present)
            return std::nullopt;
        if (before_lookup)
            before_lookup(*found);
        return found->value;
    }

    std::expected<bool, std::error_code> erase(const ebpf_pending_query_key& wanted) noexcept override {
        auto found = find(wanted);
        if (found == entries.end() || !found->present)
            return false;
        if (before_erase)
            before_erase(*found);
        if (fail_erase) {
            fail_erase = false;
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        found->present = false;
        return true;
    }

    std::vector<Entry>::iterator find(const ebpf_pending_query_key& wanted) {
        return std::find_if(entries.begin(), entries.end(), [&](const Entry& entry) { return entry.key == wanted; });
    }

    std::vector<Entry> entries;
    std::function<void(Entry&)> before_lookup;
    std::function<void(Entry&)> before_erase;
    bool fail_batch = false;
    bool fail_erase = false;
};

struct Harness {
    explicit Harness(std::vector<FakePendingMap::Entry> entries, std::chrono::nanoseconds timeout = 100ns) {
        auto fake = std::make_unique<FakePendingMap>();
        fake->entries = std::move(entries);
        map = fake.get();
        cleaner = PendingQueryCleaner::create_for_testing(EbpfNativePendingBinding(7), timeout, std::move(fake));
    }

    FakePendingMap* map;
    std::unique_ptr<PendingQueryCleaner> cleaner;
};

} // namespace

TEST_CASE("Pending cleanup reclaims expired Active and Claimed records") {
    Harness harness({ { key(1), value(10) }, { key(2), value(20, true) }, { key(3), value(150) } });
    auto result = harness.cleaner->cleanup(at(150));
    REQUIRE(result.has_value());
    CHECK(result->removed_entries == 2);
    CHECK_FALSE(result->more_work);
    CHECK_FALSE(harness.map->entries[0].present);
    CHECK_FALSE(harness.map->entries[1].present);
    CHECK(harness.map->entries[2].present);
}

TEST_CASE("Pending cleanup rechecks an Active record immediately before deletion") {
    Harness harness({ { key(1), value(10) } });
    harness.map->before_lookup = [](FakePendingMap::Entry& entry) { entry.value = value(140); };
    auto result = harness.cleaner->cleanup(at(150));
    REQUIRE(result.has_value());
    CHECK(result->removed_entries == 0);
    CHECK(harness.map->entries[0].present);
}

TEST_CASE("Pending cleanup accepts the refresh-after-recheck lost-Fill race") {
    Harness harness({ { key(1), value(10) } });
    harness.map->before_erase = [](FakePendingMap::Entry& entry) { entry.value = value(140); };
    auto result = harness.cleaner->cleanup(at(150));
    REQUIRE(result.has_value());
    CHECK(result->removed_entries == 1);
    CHECK_FALSE(harness.map->entries[0].present);
}

TEST_CASE("Pending cleanup persists its bounded batch cursor") {
    std::vector<FakePendingMap::Entry> entries;
    entries.reserve(300);
    for (uint32_t index = 0; index < 300; ++index)
        entries.push_back({ key(index + 1), value(1) });
    Harness harness(std::move(entries));

    auto first = harness.cleaner->cleanup(at(200));
    REQUIRE(first.has_value());
    CHECK(first->removed_entries == PendingQueryCleaner::kBatchSize);
    CHECK(first->more_work);

    auto second = harness.cleaner->cleanup(at(200));
    REQUIRE(second.has_value());
    CHECK(second->removed_entries == 44);
    CHECK_FALSE(second->more_work);
}

TEST_CASE("Pending cleanup resets its cursor after a map error") {
    Harness harness({ { key(1), value(10) } });
    harness.map->fail_batch = true;
    CHECK_FALSE(harness.cleaner->cleanup(at(150)).has_value());
    auto retried = harness.cleaner->cleanup(at(150));
    REQUIRE(retried.has_value());
    CHECK(retried->removed_entries == 1);
}

} // namespace shinku::backend::ebpf
