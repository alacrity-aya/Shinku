// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_hash_table.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"
#include "cache/dns/question.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <vector>

namespace shinku::backend::dpdk {

struct DpdkPendingKey {
    uint32_t source_ipv4;
    uint32_t destination_ipv4;
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t transaction_id;
    uint16_t reserved = 0;
};
static_assert(sizeof(DpdkPendingKey) == 16);

enum class DpdkPendingStoreResult : uint8_t {
    Inserted,
    Refreshed,
    Skipped,
};

class DpdkPendingStore final {
public:
    static constexpr uint32_t kNoSlot = UINT32_MAX;

    [[nodiscard]] static std::expected<std::unique_ptr<DpdkPendingStore>, std::error_code>
    create(uint32_t capacity, int socket_id) noexcept;

    ~DpdkPendingStore();

    [[nodiscard]] DpdkPendingStoreResult
    remember(const DpdkPendingKey& key, const cache::dns::DnsQuestion& question, cache::CacheTime now) noexcept;

    [[nodiscard]] std::expected<bool, std::error_code> claim(
        const DpdkPendingKey& key,
        const cache::dns::DnsQuestion& question,
        cache::CacheTime now,
        std::chrono::nanoseconds timeout
    ) noexcept;

    [[nodiscard]] std::expected<cache::CleanupResult, std::error_code>
    cleanup(cache::CacheTime now, std::chrono::nanoseconds timeout) noexcept;

private:
    struct Entry {
        DpdkPendingKey key {};
        cache::dns::DnsQuestion question {};
        cache::CacheTime last_seen;
        uint32_t next_free = kNoSlot;
        bool claimed = false;
        bool occupied = false;
    };
    using HashTable = DpdkHashTable<DpdkPendingKey, Entry>;

    DpdkPendingStore(uint32_t capacity, std::vector<Entry> entries, HashTable hash) noexcept;

    [[nodiscard]] uint32_t allocate_entry() noexcept;
    void reclaim_entry(uint32_t index) noexcept;

    uint32_t capacity_;
    std::vector<Entry> entries_;
    HashTable hash_;
    uint32_t next_unused_entry_ = 0;
    uint32_t free_head_ = kNoSlot;
    uint32_t cleanup_cursor_ = 0;
    uint32_t cleanup_remaining_ = 0;
};

} // namespace shinku::backend::dpdk
