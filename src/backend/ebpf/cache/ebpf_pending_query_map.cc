// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_pending_query_map.h"

#include <bpf/bpf.h>
#include <cerrno>
#include <memory>

namespace shinku::backend::ebpf {
namespace {

std::error_code current_error() noexcept {
    return { errno == 0 ? EIO : errno, std::generic_category() };
}

class ProductionEbpfPendingQueryMap final: public EbpfPendingQueryMap {
public:
    explicit ProductionEbpfPendingQueryMap(int map_fd) noexcept: map_fd_(map_fd) {}

    std::expected<EbpfPendingBatchResult, std::error_code> lookup_batch(
        const ebpf_pending_query_key* input_cursor,
        ebpf_pending_query_key& output_cursor,
        std::span<ebpf_pending_query_key> keys,
        std::span<ebpf_pending_query_value> values
    ) noexcept override {
        auto count = static_cast<__u32>(keys.size());
        errno = 0;
        const int result = bpf_map_lookup_batch(
            map_fd_,
            const_cast<ebpf_pending_query_key*>(input_cursor),
            &output_cursor,
            keys.data(),
            values.data(),
            &count,
            nullptr
        );
        if (result == 0)
            return EbpfPendingBatchResult { .count = count, .terminal = false };
        if (errno == ENOENT)
            return EbpfPendingBatchResult { .count = count, .terminal = true };
        return std::unexpected(current_error());
    }

    std::expected<std::optional<ebpf_pending_query_value>, std::error_code>
    lookup(const ebpf_pending_query_key& key) noexcept override {
        ebpf_pending_query_value value {};
        errno = 0;
        if (bpf_map_lookup_elem(map_fd_, &key, &value) == 0)
            return value;
        if (errno == ENOENT)
            return std::nullopt;
        return std::unexpected(current_error());
    }

    std::expected<bool, std::error_code> erase(const ebpf_pending_query_key& key) noexcept override {
        errno = 0;
        if (bpf_map_delete_elem(map_fd_, &key) == 0)
            return true;
        if (errno == ENOENT)
            return false;
        return std::unexpected(current_error());
    }

private:
    int map_fd_;
};

} // namespace

std::unique_ptr<EbpfPendingQueryMap> make_production_ebpf_pending_query_map(int map_fd) {
    return std::make_unique<ProductionEbpfPendingQueryMap>(map_fd);
}

} // namespace shinku::backend::ebpf
