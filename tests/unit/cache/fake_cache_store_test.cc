// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_store_conformance.h"

#include "cache/cache_candidate.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {

using shinku::cache::CacheCandidate;
using shinku::cache::CacheEntryKind;
using shinku::cache::CacheKey;
using shinku::cache::CacheLifetime;
using shinku::cache::CacheNamespace;
using shinku::cache::CacheStore;
using shinku::cache::CacheStoreError;
using shinku::cache::CacheStoreErrorCode;
using shinku::cache::CacheTime;
using shinku::cache::CanonicalDnsName;
using shinku::cache::CleanupResult;
using shinku::cache::StoreOutcome;
using shinku::cache::testing::CacheStoreConformanceAdapter;

class FakeCacheStore final: public CacheStore {
public:
    explicit FakeCacheStore(std::size_t capacity, std::size_t max_ttl_offsets, std::size_t cleanup_batch):
        capacity_(capacity),
        max_ttl_offsets_(max_ttl_offsets),
        cleanup_batch_(cleanup_batch) {}

    std::expected<StoreOutcome, CacheStoreError>
    store(const CacheCandidate& candidate, CacheTime now) noexcept override {
        std::scoped_lock lock(mutex_);

        if (fail_next_write_) {
            fail_next_write_ = false;
            return std::unexpected(CacheStoreError {
                .code = CacheStoreErrorCode::WriteFailed,
                .cause = std::nullopt,
            });
        }
        if (reject_next_) {
            reject_next_ = false;
            return StoreOutcome::Rejected;
        }
        if (candidate.ttl_offsets.size() > max_ttl_offsets_)
            return StoreOutcome::Rejected;
        for (uint16_t offset: candidate.ttl_offsets) {
            if (offset > candidate.response.size() || candidate.response.size() - offset < sizeof(uint32_t))
                return StoreOutcome::Rejected;
        }

        auto existing = std::find_if(entries_.begin(), entries_.end(), [&](const Record& record) {
            return record.key == candidate.key;
        });
        if (existing != entries_.end()) {
            *existing = copy_record(candidate, now);
            return StoreOutcome::Updated;
        }

        if (entries_.size() < capacity_) {
            entries_.push_back(copy_record(candidate, now));
            return StoreOutcome::Inserted;
        }

        auto expired = std::find_if(entries_.begin(), entries_.end(), [&](const Record& record) {
            return now >= record.expires_at;
        });
        if (expired != entries_.end()) {
            *expired = copy_record(candidate, now);
            return StoreOutcome::Inserted;
        }

        entries_.at(replacement_cursor_) = copy_record(candidate, now);
        replacement_cursor_ = (replacement_cursor_ + 1) % capacity_;
        return StoreOutcome::Replaced;
    }

    std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime now) noexcept override {
        std::scoped_lock lock(mutex_);
        std::size_t removed = 0;
        for (auto entry = entries_.begin(); entry != entries_.end() && removed < cleanup_batch_;) {
            if (now >= entry->expires_at) {
                entry = entries_.erase(entry);
                ++removed;
            } else {
                ++entry;
            }
        }

        const bool more_work =
            std::ranges::any_of(entries_, [&](const Record& record) { return now >= record.expires_at; });
        return CleanupResult {
            .removed_entries = removed,
            .more_work = more_work,
        };
    }

    bool hit_visible(const CacheKey& key, CacheTime now) const noexcept {
        std::scoped_lock lock(mutex_);
        return std::ranges::any_of(entries_, [&](const Record& record) {
            return record.key == key && now < record.expires_at;
        });
    }

    std::vector<std::byte> payload(const CacheKey& key) const {
        std::scoped_lock lock(mutex_);
        auto entry =
            std::find_if(entries_.begin(), entries_.end(), [&](const Record& record) { return record.key == key; });
        if (entry == entries_.end())
            return {};
        return entry->response;
    }

    void reject_next() noexcept {
        std::scoped_lock lock(mutex_);
        reject_next_ = true;
    }

    void fail_next_write() noexcept {
        std::scoped_lock lock(mutex_);
        fail_next_write_ = true;
    }

private:
    struct Record {
        CacheKey key;
        CacheEntryKind kind;
        CacheTime expires_at;
        std::vector<std::byte> response;
        std::vector<uint16_t> ttl_offsets;
    };

    static Record copy_record(const CacheCandidate& candidate, CacheTime now) {
        return Record {
            .key = candidate.key,
            .kind = candidate.kind,
            .expires_at = now + candidate.lifetime,
            .response = std::vector<std::byte>(candidate.response.begin(), candidate.response.end()),
            .ttl_offsets = std::vector<uint16_t>(candidate.ttl_offsets.begin(), candidate.ttl_offsets.end()),
        };
    }

    std::size_t capacity_;
    std::size_t max_ttl_offsets_;
    std::size_t cleanup_batch_;
    mutable std::mutex mutex_;
    std::vector<Record> entries_;
    std::size_t replacement_cursor_ = 0;
    bool reject_next_ = false;
    bool fail_next_write_ = false;
};

class FakeCacheStoreAdapter final: public CacheStoreConformanceAdapter {
public:
    FakeCacheStoreAdapter(): store_(2, 1, 1) {}

    std::expected<StoreOutcome, CacheStoreError> store(
        uint8_t key,
        uint8_t payload,
        CacheTime now,
        CacheLifetime lifetime,
        bool incomplete_patch_plan = false
    ) noexcept override {
        std::array<std::byte, 8> response {};
        response[7] = static_cast<std::byte>(payload);
        constexpr std::array<uint16_t, 1> complete_offsets { 0 };
        constexpr std::array<uint16_t, 2> incomplete_offsets { 0, 4 };
        const std::span<const uint16_t> offsets = incomplete_patch_plan ? std::span<const uint16_t>(incomplete_offsets)
                                                                        : std::span<const uint16_t>(complete_offsets);
        CacheCandidate candidate {
            .key = make_key(key),
            .kind = CacheEntryKind::Positive,
            .lifetime = lifetime,
            .response = response,
            .ttl_offsets = offsets,
        };
        return store_.store(candidate, now);
    }

    std::expected<CleanupResult, CacheStoreError> cleanup(CacheTime now) noexcept override {
        return store_.cleanup(now);
    }

    bool hit_visible(uint8_t key, CacheTime now) const noexcept override {
        return store_.hit_visible(make_key(key), now);
    }

    std::optional<uint8_t> payload(uint8_t key) const override {
        const auto response = store_.payload(make_key(key));
        if (response.empty())
            return std::nullopt;
        return std::to_integer<uint8_t>(response.back());
    }

    void reject_next() noexcept override {
        store_.reject_next();
    }

    void fail_next_write() noexcept override {
        store_.fail_next_write();
    }

private:
    static CacheKey make_key(uint8_t value) {
        const std::array<std::byte, 3> wire { std::byte { 1 }, static_cast<std::byte>('a' + value), std::byte { 0 } };
        auto name = CanonicalDnsName::from_wire(wire);
        // Test keys are fixed valid wire names.
        return CacheKey {
            .cache_namespace = CacheNamespace { .destination_ipv4 = 0x0a000001, .destination_port = 53 },
            .question_name = *name,
            .question_type = 1,
            .question_class = 1,
        };
    }

    FakeCacheStore store_;
};

} // namespace

TEST_CASE("FakeCacheStore satisfies the reusable Cache Store contract") {
    shinku::cache::testing::run_cache_store_conformance([] { return std::make_unique<FakeCacheStoreAdapter>(); });
}
