// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_pending_query_map.h"

#include <bpf/bpf.h>
#include <cerrno>
#include <memory>

namespace shinku::backend::ebpf {
namespace {

/// Build a std::error_code from the current errno, using EIO when errno is 0.
std::error_code current_error() noexcept {
    return { errno == 0 ? EIO : errno, std::generic_category() };
}

/// Production @ref EbpfPendingQueryMap backed by a real BPF pending-query map fd.
class ProductionEbpfPendingQueryMap final: public EbpfPendingQueryMap {
public:
    /// Wrap the given BPF pending-query map file descriptor.
    explicit ProductionEbpfPendingQueryMap(int map_fd) noexcept: map_fd_(map_fd) {}

    /// Look up the next batch starting at @p input_cursor (null starts from the
    /// beginning), advancing @p output_cursor for the next call; ENOENT marks
    /// the end of the map.
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

    /// Point-lookup @p key; ENOENT becomes an empty optional and other errors propagate.
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

    /// Delete @p key, returning true if an entry was erased, false if absent, or an error.
    std::expected<bool, std::error_code> erase(const ebpf_pending_query_key& key) noexcept override {
        errno = 0;
        if (bpf_map_delete_elem(map_fd_, &key) == 0)
            return true;
        if (errno == ENOENT)
            return false;
        return std::unexpected(current_error());
    }

private:
    int map_fd_; ///< File descriptor of the BPF pending-query map.
};

} // namespace

/// Create the production pending-query-map wrapper over the given BPF map fd.
std::unique_ptr<EbpfPendingQueryMap> make_production_ebpf_pending_query_map(int map_fd) {
    return std::make_unique<ProductionEbpfPendingQueryMap>(map_fd);
}

} // namespace shinku::backend::ebpf
