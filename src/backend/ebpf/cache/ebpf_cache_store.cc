// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_store.h"

#include "cache/cache_candidate.h"
#include "cache/cache_key.h"
#include "cache/cache_store_error.h"
#include "cache/cache_time.h"
#include "ebpf_cache_fingerprint.h"
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <span>
#include <utility>

namespace shinku::backend::ebpf {
namespace {

using cache::CacheStoreError;
using cache::CacheStoreErrorCode;

CacheStoreError storage_error(std::error_code cause) noexcept {
    return { .code = CacheStoreErrorCode::StorageUnavailable, .cause = cause };
}

CacheStoreError write_error(std::error_code cause) noexcept {
    return { .code = CacheStoreErrorCode::WriteFailed, .cause = cause };
}

CacheStoreError cleanup_error(std::error_code cause) noexcept {
    return { .code = CacheStoreErrorCode::CleanupFailed, .cause = cause };
}

std::pair<uint64_t, uint64_t> timestamps(cache::CacheTime observed_at, cache::CacheLifetime lifetime) noexcept {
    constexpr uint64_t nanoseconds_per_second = 1'000'000'000ULL;
    const auto stored_at = static_cast<uint64_t>(observed_at.time_since_epoch().count());
    const auto lifetime_ns = static_cast<uint64_t>(lifetime.count()) * nanoseconds_per_second;
    return { stored_at, stored_at + lifetime_ns };
}

ebpf_cache_publication publication(uint32_t slot_index, uint64_t generation) noexcept {
    return {
        .slot_index = slot_index,
        .reserved = 0,
        .generation = generation,
    };
}

} // namespace

EbpfCacheStore::EbpfCacheStore(
    EbpfCacheStorageLayout layout,
    EbpfNativeStorageBinding binding,
    ebpf_cache_secret secret,
    std::unique_ptr<EbpfCacheMap> map
):
    layout_(layout),
    binding_(std::move(binding)),
    secret_(secret),
    map_(std::move(map)),
    slots_(layout.entry_capacity) {
    // Start each Header lifetime without clearing inactive slot body or tail bytes.
    for (uint32_t slot_index = 0; slot_index < layout_.entry_capacity; ++slot_index) {
        auto* const header = reinterpret_cast<ebpf_cache_slot_header*>(
            binding_.arena().data() + (static_cast<size_t>(slot_index) * layout_.slot_stride)
        );
        std::construct_at(header);
    }
}

std::unique_ptr<EbpfCacheStore>
EbpfCacheStore::create(EbpfCacheStorageLayout layout, EbpfNativeStorageBinding binding, ebpf_cache_secret secret) {
    auto map = make_production_ebpf_cache_map(binding.cache_map_fd());
    return create_for_testing(layout, std::move(binding), secret, std::move(map));
}

std::unique_ptr<EbpfCacheStore> EbpfCacheStore::create_for_testing(
    EbpfCacheStorageLayout layout,
    EbpfNativeStorageBinding binding,
    ebpf_cache_secret secret,
    std::unique_ptr<EbpfCacheMap> map
) {
    return std::unique_ptr<EbpfCacheStore>(new EbpfCacheStore(layout, std::move(binding), secret, std::move(map)));
}

ebpf_cache_physical_key EbpfCacheStore::physical_key(const cache::CacheKey& key) const noexcept {
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
            &secret_
        ),
    };
}

std::byte* EbpfCacheStore::slot(uint32_t slot_index) noexcept {
    assert(slot_index < layout_.entry_capacity);
    return binding_.arena().data() + (static_cast<size_t>(slot_index) * layout_.slot_stride);
}

// overwrap
uint64_t EbpfCacheStore::next_generation() noexcept {
    return next_generation_++;
}

uint32_t EbpfCacheStore::allocate_slot() noexcept {
    if (free_head_ != kNoSlot) {
        const uint32_t result = free_head_;
        free_head_ = slots_[result].next_free;
        slots_[result].next_free = kNoSlot;
        return result;
    }
    if (next_unused_slot_ < layout_.entry_capacity)
        return next_unused_slot_++;

    const uint32_t result = replacement_cursor_;
    assert(slots_[result].generation != 0);
    return result;
}

void EbpfCacheStore::reclaim_slot(uint32_t slot_index) noexcept {
    SlotRecord& record = slots_[slot_index];
    record.key = {};
    record.generation = 0;
    record.expires_at_ns = 0;
    record.next_free = free_head_;
    free_head_ = slot_index;
}

void EbpfCacheStore::write_slot(
    uint32_t slot_index,
    const cache::CacheCandidate& candidate,
    uint64_t stored_at_ns,
    uint64_t expires_at_ns,
    uint64_t generation
) noexcept {
    std::byte* const bytes = slot(slot_index);
    auto* const header = reinterpret_cast<ebpf_cache_slot_header*>(bytes);
    const std::atomic_ref sequence(header->sequence);
    const uint32_t old_sequence = sequence.fetch_add(1, std::memory_order_acq_rel);
    assert((old_sequence & 1U) == 0);

    header->response_size = static_cast<uint16_t>(candidate.response.size());
    header->ttl_offset_count = static_cast<uint16_t>(candidate.ttl_offsets.size());
    header->generation = generation;
    header->stored_at_ns = stored_at_ns;
    header->expires_at_ns = expires_at_ns;

    std::memcpy(bytes + sizeof(*header), candidate.response.data(), candidate.response.size());
    const size_t offset_table = ebpf_cache_offset_table_offset(candidate.response.size());
    if (offset_table > sizeof(*header) + candidate.response.size())
        bytes[offset_table - 1U] = std::byte { 0 };
    if (!candidate.ttl_offsets.empty())
        std::memcpy(bytes + offset_table, candidate.ttl_offsets.data(), candidate.ttl_offsets.size_bytes());
    sequence.fetch_add(1, std::memory_order_release);
}

void EbpfCacheStore::restore_slot_body(uint32_t slot_index, size_t body_size) noexcept {
    std::byte* const bytes = slot(slot_index);
    auto* const header = reinterpret_cast<ebpf_cache_slot_header*>(bytes);
    const std::atomic_ref sequence(header->sequence);
    const uint32_t old_sequence = sequence.fetch_add(1, std::memory_order_acq_rel);
    assert((old_sequence & 1U) == 0);
    std::memcpy(bytes + sizeof(uint32_t), rollback_scratch_.data(), body_size);
    sequence.fetch_add(1, std::memory_order_release);
}

std::expected<cache::StoreOutcome, cache::CacheStoreError> EbpfCacheStore::store(
    const cache::CacheCandidate& candidate,
    cache::CacheTime observed_at,
    cache::CacheTime now
) noexcept {
    const auto [stored_at, expires_at] = timestamps(observed_at, candidate.lifetime);
    if (expires_at <= static_cast<uint64_t>(now.time_since_epoch().count()))
        return cache::StoreOutcome::Rejected;

    std::scoped_lock lock(mutex_);

    // The physical key is the hash-map key; the publication it maps to points
    // at the arena slot where the response bytes live.
    const ebpf_cache_physical_key key = physical_key(candidate.key);
    auto existing = map_->lookup(key);
    if (!existing)
        return std::unexpected(storage_error(existing.error()));

    if (*existing) {
        // Update-in-place path: the key is already published to a live slot.
        const ebpf_cache_publication old_publication = **existing;
        SlotRecord& owner = slots_[old_publication.slot_index];

        // Backup the current entry's active bytes (everything after the seqlock
        // `sequence` word) so a failed map update can roll the slot back.
        const auto* old_header = reinterpret_cast<const ebpf_cache_slot_header*>(slot(old_publication.slot_index));
        if (stored_at <= old_header->stored_at_ns)
            return cache::StoreOutcome::Rejected;
        const size_t old_active_size =
            ebpf_cache_active_slot_size(old_header->response_size, old_header->ttl_offset_count);

        // Host-side bookkeeping and the BPF-published metadata must agree.
        assert(old_publication.slot_index < layout_.entry_capacity);
        assert(owner.generation == old_publication.generation);
        assert(owner.key == key);
        assert(old_active_size <= layout_.slot_stride);

        // The `sequence` word is the seqlock marker; the body is bytes[4, active).
        const size_t old_body_size = old_active_size - sizeof(uint32_t);
        std::memcpy(rollback_scratch_.data(), slot(old_publication.slot_index) + sizeof(uint32_t), old_body_size);

        // Write the arena slot first (reversible), then publish to the BPF map.
        // The fresh generation makes in-flight readers of the old entry miss.
        const uint64_t generation = next_generation();
        write_slot(old_publication.slot_index, candidate, stored_at, expires_at, generation);
        auto published =
            map_->update(key, publication(old_publication.slot_index, generation), EbpfCacheMapUpdateMode::Update);
        if (!published) {
            // The map still references the old generation; restore the old bytes
            // so the arena matches the publication again.
            restore_slot_body(old_publication.slot_index, old_body_size);
            return std::unexpected(write_error(published.error()));
        }

        owner.generation = generation;
        owner.expires_at_ns = expires_at;
        return cache::StoreOutcome::Updated;
    }

    // Insert path: allocate a slot (free list, then never-used slots, then the
    // replacement cursor that evicts an existing occupant).
    const uint32_t slot_index = allocate_slot();
    SlotRecord& owner = slots_[slot_index];
    const bool occupied = owner.generation != 0;
    const auto admission_ns = static_cast<uint64_t>(now.time_since_epoch().count());
    const bool expired_victim = occupied && owner.expires_at_ns <= admission_ns;
    if (occupied) {
        // Evict: drop the old key from the map before reusing its slot.
        auto erased = map_->erase(owner.key);
        if (!erased)
            return std::unexpected(write_error(erased.error()));
        replacement_cursor_ = (slot_index + 1U) % layout_.entry_capacity;
    }

    const uint64_t generation = next_generation();
    write_slot(slot_index, candidate, stored_at, expires_at, generation);
    auto published = map_->update(key, publication(slot_index, generation), EbpfCacheMapUpdateMode::Insert);
    if (!published) {
        // Undo the slot allocation so the failed insert leaves no trace.
        reclaim_slot(slot_index);
        return std::unexpected(write_error(published.error()));
    }

    owner.key = key;
    owner.generation = generation;
    owner.expires_at_ns = expires_at;
    owner.next_free = kNoSlot;
    // Inserted: brand-new slot, or we evicted an already-expired victim.
    // Replaced: we evicted a still-live entry to make room.
    if (!occupied || expired_victim)
        return cache::StoreOutcome::Inserted;
    return cache::StoreOutcome::Replaced;
}

std::expected<cache::CleanupResult, cache::CacheStoreError> EbpfCacheStore::cleanup(cache::CacheTime now) noexcept {
    const auto time = now.time_since_epoch().count();
    const auto now_ns = static_cast<uint64_t>(time);

    std::scoped_lock lock(mutex_);
    if (cleanup_remaining_ == 0)
        cleanup_remaining_ = layout_.entry_capacity;

    size_t removed = 0;
    const auto count = std::min<size_t>(cleanup_remaining_, kCleanupBatchSize);
    for (size_t scanned = 0; scanned < count; ++scanned) {
        SlotRecord& owner = slots_[cleanup_cursor_];
        if (owner.generation != 0 && owner.expires_at_ns <= now_ns) {
            auto erased = map_->erase(owner.key);
            if (!erased)
                return std::unexpected(cleanup_error(erased.error()));
            reclaim_slot(cleanup_cursor_);
            ++removed;
        }
        cleanup_cursor_ = (cleanup_cursor_ + 1U) % layout_.entry_capacity;
        --cleanup_remaining_;
    }

    return cache::CleanupResult {
        .removed_entries = removed,
        .more_work = cleanup_remaining_ != 0,
    };
}

} // namespace shinku::backend::ebpf
