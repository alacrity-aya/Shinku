// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_cache_store.h"

#include "backend/dpdk/dpdk_hash_table.h"
#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/cache_store.h"
#include "cache/cache_store_error.h"
#include "cache/cache_time.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <mutex>
#include <new>
#include <rte_byteorder.h>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

cache::CacheStoreError error(cache::CacheStoreErrorCode code, std::error_code cause) noexcept {
    return { .code = code, .cause = cause };
}

} // namespace

DpdkCacheStore::DpdkCacheStore(
    uint32_t capacity,
    uint32_t maximum_response_bytes,
    std::vector<Entry> entries,
    HashTable hash
) noexcept:
    capacity_(capacity),
    maximum_response_bytes_(maximum_response_bytes),
    entries_(std::move(entries)),
    hash_(std::move(hash)) {}

std::expected<std::unique_ptr<DpdkCacheStore>, cache::CacheStoreError>
DpdkCacheStore::create(uint32_t capacity, uint32_t maximum_response_bytes, int socket_id) noexcept {
    try {
        std::vector<Entry> entries(capacity);
        auto hash = HashTable::create("shinku-dpdk-cache", capacity, socket_id);
        if (!hash)
            return std::unexpected(error(cache::CacheStoreErrorCode::StorageUnavailable, hash.error()));
        return std::unique_ptr<DpdkCacheStore>(
            new DpdkCacheStore(capacity, maximum_response_bytes, std::move(entries), std::move(*hash))
        );
    } catch (const std::bad_alloc&) {
        return std::unexpected(cache::CacheStoreError {
            .code = cache::CacheStoreErrorCode::StorageUnavailable,
            .cause = std::make_error_code(std::errc::not_enough_memory),
        });
    }
}

DpdkCacheStore::~DpdkCacheStore() = default;

DpdkCacheStore::PhysicalKey DpdkCacheStore::physical_key(const cache::CacheKey& key) noexcept {
    PhysicalKey result {};
    const uint32_t destination_ipv4 = rte_cpu_to_be_32(key.cache_namespace.destination_ipv4);
    const uint16_t destination_port = rte_cpu_to_be_16(key.cache_namespace.destination_port);
    const uint16_t question_type = rte_cpu_to_be_16(key.question_type);
    const uint16_t question_class = rte_cpu_to_be_16(key.question_class);
    const uint16_t name_size = rte_cpu_to_be_16(static_cast<uint16_t>(key.question_name.size()));
    std::memcpy(result.data(), &destination_ipv4, sizeof(destination_ipv4));
    std::memcpy(result.data() + 4, &destination_port, sizeof(destination_port));
    std::memcpy(result.data() + 6, &question_type, sizeof(question_type));
    std::memcpy(result.data() + 8, &question_class, sizeof(question_class));
    std::memcpy(result.data() + 10, &name_size, sizeof(name_size));
    const auto name = key.question_name.wire();
    std::memcpy(result.data() + 12, name.data(), name.size());
    return result;
}

uint32_t DpdkCacheStore::allocate_entry() noexcept {
    if (free_head_ != kNoSlot) {
        const uint32_t index = free_head_;
        free_head_ = entries_[index].next_free;
        entries_[index].next_free = kNoSlot;
        return index;
    }
    if (next_unused_entry_ < capacity_)
        return next_unused_entry_++;
    return replacement_cursor_;
}

void DpdkCacheStore::reclaim_entry(uint32_t index) noexcept {
    Entry& entry = entries_[index];
    entry.occupied = false;
    entry.next_free = free_head_;
    free_head_ = index;
}

void DpdkCacheStore::write_entry(
    Entry& entry,
    const cache::CacheCandidate& candidate,
    cache::CacheTime observed_at
) noexcept {
    entry.physical_key = physical_key(candidate.key);
    entry.kind = candidate.kind;
    entry.stored_at = observed_at;
    entry.expires_at = observed_at + candidate.lifetime;
    entry.response_size = static_cast<uint16_t>(candidate.response.size());
    entry.ttl_offset_count = static_cast<uint16_t>(candidate.ttl_offsets.size());
    std::ranges::copy(candidate.response, entry.response.begin());
    std::ranges::copy(candidate.ttl_offsets, entry.ttl_offsets.begin());
}

std::expected<void, std::error_code> DpdkCacheStore::erase_entry(Entry& entry) noexcept {
    return hash_.erase(entry.physical_key);
}

std::expected<cache::StoreOutcome, cache::CacheStoreError> DpdkCacheStore::store(
    const cache::CacheCandidate& candidate,
    cache::CacheTime observed_at,
    cache::CacheTime now
) noexcept {
    if (candidate.response.size() > maximum_response_bytes_ || candidate.response.size() > kResponseBytes
        || candidate.ttl_offsets.size() > kTtlOffsetCount)
        return cache::StoreOutcome::Rejected;
    if (observed_at + candidate.lifetime <= now)
        return cache::StoreOutcome::Rejected;

    const PhysicalKey key = physical_key(candidate.key);
    const std::scoped_lock lock(mutex_);
    auto existing = hash_.lookup(key);
    if (!existing)
        return std::unexpected(error(cache::CacheStoreErrorCode::StorageUnavailable, existing.error()));
    if (*existing != nullptr) {
        auto* entry = *existing;
        if (observed_at <= entry->stored_at)
            return cache::StoreOutcome::Rejected;
        write_entry(*entry, candidate, observed_at);
        return cache::StoreOutcome::Updated;
    }

    const uint32_t index = allocate_entry();
    Entry& entry = entries_[index];
    const bool occupied = entry.occupied;
    const bool expired_victim = occupied && now >= entry.expires_at;
    if (occupied) {
        if (auto result = erase_entry(entry); !result)
            return std::unexpected(error(cache::CacheStoreErrorCode::WriteFailed, result.error()));
        replacement_cursor_ = (index + 1U) % capacity_;
    }

    write_entry(entry, candidate, observed_at);
    if (auto result = hash_.insert(key, entry); !result) {
        reclaim_entry(index);
        return std::unexpected(error(cache::CacheStoreErrorCode::WriteFailed, result.error()));
    }
    entry.occupied = true;
    entry.next_free = kNoSlot;
    if (!occupied || expired_victim)
        return cache::StoreOutcome::Inserted;
    return cache::StoreOutcome::Replaced;
}

const DpdkCacheStore::Entry* DpdkCacheStore::lookup(const cache::CacheKey& key, cache::CacheTime now) const noexcept {
    const PhysicalKey physical = physical_key(key);
    auto result = hash_.lookup(physical);
    if (!result || *result == nullptr)
        return nullptr;
    const auto* entry = *result;
    return entry->occupied && now < entry->expires_at ? entry : nullptr;
}

std::expected<cache::CleanupResult, cache::CacheStoreError> DpdkCacheStore::cleanup(cache::CacheTime now) noexcept {
    const std::scoped_lock lock(mutex_);
    if (cleanup_remaining_ == 0)
        cleanup_remaining_ = capacity_;
    const uint32_t count = std::min<uint32_t>(cleanup_remaining_, kCleanupBatchSize);
    size_t removed = 0;
    for (uint32_t scanned = 0; scanned < count; ++scanned) {
        Entry& entry = entries_[cleanup_cursor_];
        if (entry.occupied && now >= entry.expires_at) {
            if (auto result = erase_entry(entry); !result) {
                cleanup_remaining_ = 0;
                return std::unexpected(error(cache::CacheStoreErrorCode::CleanupFailed, result.error()));
            }
            reclaim_entry(cleanup_cursor_);
            ++removed;
        }
        cleanup_cursor_ = (cleanup_cursor_ + 1U) % capacity_;
        --cleanup_remaining_;
    }
    return cache::CleanupResult { .removed_entries = removed, .more_work = cleanup_remaining_ != 0 };
}

} // namespace shinku::backend::dpdk
