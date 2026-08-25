// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <system_error>
#include <type_traits>
#include <utility>

struct rte_hash;

namespace shinku::backend::dpdk {

template<typename Key, typename Value>
class DpdkHashTable;

namespace detail {

/**
 * @brief Type-erased RAII wrapper around a DPDK rte_hash.
 *
 * Owned exclusively by @ref DpdkHashTable; the storage layer keeps the key
 * size and value indirection untyped so the templated wrapper can stay small.
 */
class DpdkHashTableStorage final {
public:
    DpdkHashTableStorage(DpdkHashTableStorage&&) noexcept = default;
    DpdkHashTableStorage& operator=(DpdkHashTableStorage&&) noexcept = default;

    DpdkHashTableStorage(const DpdkHashTableStorage&) = delete;
    DpdkHashTableStorage& operator=(const DpdkHashTableStorage&) = delete;

private:
    template<typename Key, typename Value>
    friend class shinku::backend::dpdk::DpdkHashTable;

    /// Custom deleter that frees the rte_hash via rte_hash_free.
    struct Deleter {
        void operator()(rte_hash* hash) const noexcept;
    };

    /**
     * @brief Create a rte_hash with the given parameters.
     * @param name Name for the hash (used in DPDK diagnostics).
     * @param capacity Maximum number of entries.
     * @param key_size Size of each key in bytes.
     * @param socket_id NUMA socket to allocate on.
     * @return The storage, or a std::error_code on failure.
     */
    [[nodiscard]] static std::expected<DpdkHashTableStorage, std::error_code>
    create(const char* name, uint32_t capacity, uint32_t key_size, int socket_id) noexcept;

    explicit DpdkHashTableStorage(std::unique_ptr<rte_hash, Deleter> hash) noexcept;

    /// @brief Look up the value pointer stored for @p key.
    [[nodiscard]] std::expected<void*, std::error_code> lookup(const void* key) const noexcept;
    /// @brief Insert (or update) the value pointer for @p key.
    [[nodiscard]] std::expected<void, std::error_code> insert(const void* key, void* value) noexcept;
    /// @brief Erase the entry for @p key, if present.
    [[nodiscard]] std::expected<void, std::error_code> erase(const void* key) noexcept;

    std::unique_ptr<rte_hash, Deleter> hash_;
};

} // namespace detail

/**
 * @brief Strongly-typed hash table backed by a DPDK rte_hash.
 *
 * Keys must be trivially copyable; they are copied as raw bytes. Values are
 * stored by pointer, so callers must keep the value object alive for as long
 * as it remains in the table.
 *
 * @tparam Key The key type (must be trivially copyable).
 * @tparam Value The value type.
 */
template<typename Key, typename Value>
class DpdkHashTable final {
    static_assert(std::is_trivially_copyable_v<Key>, "DPDK hash keys are copied as raw bytes");

public:
    /**
     * @brief Create a hash table sized for @p capacity entries.
     * @param name Name for the underlying rte_hash.
     * @param capacity Maximum number of entries.
     * @param socket_id NUMA socket to allocate on.
     * @return The table, or a std::error_code on failure.
     */
    [[nodiscard]] static std::expected<DpdkHashTable, std::error_code>
    create(const char* name, uint32_t capacity, int socket_id) noexcept {
        auto storage = detail::DpdkHashTableStorage::create(name, capacity, sizeof(Key), socket_id);
        if (!storage)
            return std::unexpected(storage.error());
        return DpdkHashTable(std::move(*storage));
    }

    DpdkHashTable(DpdkHashTable&&) noexcept = default;
    DpdkHashTable& operator=(DpdkHashTable&&) noexcept = default;

    DpdkHashTable(const DpdkHashTable&) = delete;
    DpdkHashTable& operator=(const DpdkHashTable&) = delete;

    /// @brief Look up the value pointer stored for @p key (mutable).
    [[nodiscard]] std::expected<Value*, std::error_code> lookup(const Key& key) noexcept {
        auto result = storage_.lookup(&key);
        if (!result)
            return std::unexpected(result.error());
        return static_cast<Value*>(*result);
    }
    /// @brief Look up the value pointer stored for @p key (const).
    [[nodiscard]] std::expected<const Value*, std::error_code> lookup(const Key& key) const noexcept {
        auto result = storage_.lookup(&key);
        if (!result)
            return std::unexpected(result.error());
        return static_cast<const Value*>(*result);
    }
    /// @brief Insert (or update) the value pointer for @p key.
    [[nodiscard]] std::expected<void, std::error_code> insert(const Key& key, Value& value) noexcept {
        return storage_.insert(&key, &value);
    }
    /// @brief Erase the entry for @p key, if present.
    [[nodiscard]] std::expected<void, std::error_code> erase(const Key& key) noexcept {
        return storage_.erase(&key);
    }

private:
    explicit DpdkHashTable(detail::DpdkHashTableStorage storage) noexcept: storage_(std::move(storage)) {}

    detail::DpdkHashTableStorage storage_;
};

} // namespace shinku::backend::dpdk
