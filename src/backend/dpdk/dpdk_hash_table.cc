// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_hash_table.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <expected>
#include <memory>
#include <rte_errno.h>
#include <rte_hash.h>
#include <system_error>
#include <utility>

namespace shinku::backend::dpdk::detail {
namespace {

constexpr uint32_t kMinimumHashEntries = 8;

} // namespace

void DpdkHashTableStorage::Deleter::operator()(rte_hash* hash) const noexcept {
    rte_hash_free(hash);
}

DpdkHashTableStorage::DpdkHashTableStorage(std::unique_ptr<rte_hash, Deleter> hash) noexcept: hash_(std::move(hash)) {}

std::expected<DpdkHashTableStorage, std::error_code>
DpdkHashTableStorage::create(const char* name, uint32_t capacity, uint32_t key_size, int socket_id) noexcept {
    const rte_hash_parameters parameters {
        .name = name,
        .entries = std::max(capacity, kMinimumHashEntries),
        .reserved = 0,
        .key_len = key_size,
        .hash_func = nullptr,
        .hash_func_init_val = 0,
        .socket_id = socket_id,
        .extra_flag = 0,
    };
    rte_errno = 0;
    std::unique_ptr<rte_hash, Deleter> hash(rte_hash_create(&parameters));
    if (!hash) {
        assert(rte_errno != 0);
        return std::unexpected(std::error_code(rte_errno, std::generic_category()));
    }
    return DpdkHashTableStorage(std::move(hash));
}

std::expected<void*, std::error_code> DpdkHashTableStorage::lookup(const void* key) const noexcept {
    void* value = nullptr;
    const int result = rte_hash_lookup_data(hash_.get(), key, &value);
    if (result >= 0)
        return value;
    if (result == -ENOENT)
        return nullptr;

    assert(result == -EINVAL);
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
}

std::expected<void, std::error_code> DpdkHashTableStorage::insert(const void* key, void* value) noexcept {
    const int result = rte_hash_add_key_data(hash_.get(), key, value);
    if (result == 0)
        return {};
    if (result == -EINVAL)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    assert(result == -ENOSPC);
    return std::unexpected(std::make_error_code(std::errc::no_space_on_device));
}

std::expected<void, std::error_code> DpdkHashTableStorage::erase(const void* key) noexcept {
    const int result = rte_hash_del_key(hash_.get(), key);
    if (result >= 0)
        return {};
    if (result == -ENOENT)
        return std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory));

    assert(result == -EINVAL);
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
}

} // namespace shinku::backend::dpdk::detail
