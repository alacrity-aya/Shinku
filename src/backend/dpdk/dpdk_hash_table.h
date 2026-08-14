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

class DpdkHashTableStorage final {
public:
    DpdkHashTableStorage(DpdkHashTableStorage&&) noexcept = default;
    DpdkHashTableStorage& operator=(DpdkHashTableStorage&&) noexcept = default;

    DpdkHashTableStorage(const DpdkHashTableStorage&) = delete;
    DpdkHashTableStorage& operator=(const DpdkHashTableStorage&) = delete;

private:
    template<typename Key, typename Value>
    friend class shinku::backend::dpdk::DpdkHashTable;

    struct Deleter {
        void operator()(rte_hash* hash) const noexcept;
    };

    [[nodiscard]] static std::expected<DpdkHashTableStorage, std::error_code>
    create(const char* name, uint32_t capacity, uint32_t key_size, int socket_id) noexcept;

    explicit DpdkHashTableStorage(std::unique_ptr<rte_hash, Deleter> hash) noexcept;

    [[nodiscard]] std::expected<void*, std::error_code> lookup(const void* key) const noexcept;
    [[nodiscard]] std::expected<void, std::error_code> insert(const void* key, void* value) noexcept;
    [[nodiscard]] std::expected<void, std::error_code> erase(const void* key) noexcept;

    std::unique_ptr<rte_hash, Deleter> hash_;
};

} // namespace detail

template<typename Key, typename Value>
class DpdkHashTable final {
    static_assert(std::is_trivially_copyable_v<Key>, "DPDK hash keys are copied as raw bytes");

public:
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

    [[nodiscard]] std::expected<Value*, std::error_code> lookup(const Key& key) noexcept {
        auto result = storage_.lookup(&key);
        if (!result)
            return std::unexpected(result.error());
        return static_cast<Value*>(*result);
    }

    [[nodiscard]] std::expected<const Value*, std::error_code> lookup(const Key& key) const noexcept {
        auto result = storage_.lookup(&key);
        if (!result)
            return std::unexpected(result.error());
        return static_cast<const Value*>(*result);
    }

    [[nodiscard]] std::expected<void, std::error_code> insert(const Key& key, Value& value) noexcept {
        return storage_.insert(&key, &value);
    }

    [[nodiscard]] std::expected<void, std::error_code> erase(const Key& key) noexcept {
        return storage_.erase(&key);
    }

private:
    explicit DpdkHashTable(detail::DpdkHashTableStorage storage) noexcept: storage_(std::move(storage)) {}

    detail::DpdkHashTableStorage storage_;
};

} // namespace shinku::backend::dpdk
