// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_pending_store.h"

#include "backend/dpdk/dpdk_hash_table.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"
#include "cache/dns/question.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

/// True when @p last_seen is not a valid past timestamp for @p now (clock skew) or has
/// already aged past @p timeout.
bool expired(cache::CacheTime last_seen, cache::CacheTime now, std::chrono::nanoseconds timeout) noexcept {
    return now < last_seen || now - last_seen >= timeout;
}

} // namespace

/// Store the preallocated entry slab, backing hash table, and capacity.
DpdkPendingStore::DpdkPendingStore(uint32_t capacity, std::vector<Entry> entries, HashTable hash) noexcept:
    capacity_(capacity),
    entries_(std::move(entries)),
    hash_(std::move(hash)) {}

/// Allocate the entry slab and backing hash table, mapping allocation failure to a
/// not-enough-memory error.
std::expected<std::unique_ptr<DpdkPendingStore>, std::error_code>
DpdkPendingStore::create(uint32_t capacity, int socket_id) noexcept {
    try {
        std::vector<Entry> entries(capacity);
        auto hash = HashTable::create("shinku-dpdk-pending", capacity, socket_id);
        if (!hash)
            return std::unexpected(hash.error());
        return std::unique_ptr<DpdkPendingStore>(new DpdkPendingStore(capacity, std::move(entries), std::move(*hash)));
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
}

/// Trivial default destructor; destroys the entry slab and backing hash table.
DpdkPendingStore::~DpdkPendingStore() = default;

/// Pop a free slot from the free list, or the next never-used slot; kNoSlot when the slab is
/// fully occupied.
uint32_t DpdkPendingStore::allocate_entry() noexcept {
    if (free_head_ != kNoSlot) {
        const uint32_t index = free_head_;
        free_head_ = entries_[index].next_free;
        entries_[index].next_free = kNoSlot;
        return index;
    }
    if (next_unused_entry_ < capacity_)
        return next_unused_entry_++;
    return kNoSlot;
}

/// Return a slot to the free list, clearing its occupancy and claim state for reuse.
void DpdkPendingStore::reclaim_entry(uint32_t index) noexcept {
    Entry& entry = entries_[index];
    entry.occupied = false;
    entry.claimed = false;
    entry.next_free = free_head_;
    free_head_ = index;
}

/// Record or refresh a pending query: bump the timestamp of a matching unclaimed entry,
/// otherwise insert a fresh slot (reclaimed again if the hash insert fails).
DpdkPendingStoreResult DpdkPendingStore::remember(
    const DpdkPendingKey& key,
    const cache::dns::DnsQuestion& question,
    cache::CacheTime now
) noexcept {
    auto existing = hash_.lookup(key);
    if (!existing)
        return DpdkPendingStoreResult::Skipped;
    if (*existing != nullptr) {
        auto& entry = **existing;
        if (!entry.claimed && entry.question == question) {
            entry.last_seen = now;
            return DpdkPendingStoreResult::Refreshed;
        }
        return DpdkPendingStoreResult::Skipped;
    }

    const uint32_t index = allocate_entry();
    if (index == kNoSlot)
        return DpdkPendingStoreResult::Skipped;
    auto& entry = entries_[index];
    entry.key = key;
    entry.question = question;
    entry.last_seen = now;
    entry.claimed = false;
    entry.occupied = true;
    if (auto result = hash_.insert(key, entry); !result) {
        reclaim_entry(index);
        return DpdkPendingStoreResult::Skipped;
    }
    return DpdkPendingStoreResult::Inserted;
}

/// Claim an unclaimed, unexpired, question-matching entry for a response, marking it claimed
/// so the response is processed exactly once.
std::expected<bool, std::error_code> DpdkPendingStore::claim(
    const DpdkPendingKey& key,
    const cache::dns::DnsQuestion& question,
    cache::CacheTime now,
    std::chrono::nanoseconds timeout
) noexcept {
    auto existing = hash_.lookup(key);
    if (!existing)
        return std::unexpected(existing.error());
    if (*existing == nullptr)
        return false;
    auto& entry = **existing;
    if (entry.claimed || entry.question != question || expired(entry.last_seen, now, timeout))
        return false;
    entry.claimed = true;
    return true;
}

/// Reap up to 32 expired entries per call, walking a round-robin cursor across the slab;
/// more_work stays true until every slot has been swept this round.
std::expected<cache::CleanupResult, std::error_code>
DpdkPendingStore::cleanup(cache::CacheTime now, std::chrono::nanoseconds timeout) noexcept {
    if (cleanup_remaining_ == 0)
        cleanup_remaining_ = capacity_;
    const uint32_t count = std::min<uint32_t>(cleanup_remaining_, 32);
    size_t removed = 0;
    for (uint32_t scanned = 0; scanned < count; ++scanned) {
        auto& entry = entries_[cleanup_cursor_];
        if (entry.occupied && expired(entry.last_seen, now, timeout)) {
            if (auto result = hash_.erase(entry.key); !result) {
                cleanup_remaining_ = 0;
                return std::unexpected(result.error());
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
