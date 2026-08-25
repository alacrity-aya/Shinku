// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_map.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <expected>
#include <linux/bpf.h>
#include <memory>
#include <optional>
#include <system_error>

namespace shinku::backend::ebpf {
namespace {

/// Build a std::error_code from the current errno, using EIO when errno is 0.
std::error_code current_error() noexcept {
    return { errno == 0 ? EIO : errno, std::generic_category() };
}

/// Production @ref EbpfCacheMap backed by a real BPF hash map fd, translating
/// libbpf return values and errno into expected results.
class ProductionEbpfCacheMap final: public EbpfCacheMap {
public:
    /// Wrap the given BPF cache-map file descriptor.
    explicit ProductionEbpfCacheMap(int map_fd) noexcept: map_fd_(map_fd) {}

    /// Look up @p key; ENOENT becomes an empty optional and other errors propagate.
    std::expected<std::optional<ebpf_cache_publication>, std::error_code> lookup(const ebpf_cache_physical_key& key
    ) noexcept override {
        ebpf_cache_publication publication {};
        errno = 0;
        if (bpf_map_lookup_elem(map_fd_, &key, &publication) == 0)
            return publication;
        if (errno == ENOENT)
            return std::nullopt;
        return std::unexpected(current_error());
    }

    /// Insert or update @p key, mapping @p mode to the BPF_NOEXIST/BPF_EXIST flag.
    std::expected<void, std::error_code> update(
        const ebpf_cache_physical_key& key,
        const ebpf_cache_publication& publication,
        EbpfCacheMapUpdateMode mode
    ) noexcept override {
        const __u64 flags = mode == EbpfCacheMapUpdateMode::Insert ? BPF_NOEXIST : BPF_EXIST;
        errno = 0;
        if (bpf_map_update_elem(map_fd_, &key, &publication, flags) == 0)
            return {};
        return std::unexpected(current_error());
    }

    /// Delete @p key, propagating any libbpf failure as an error.
    std::expected<void, std::error_code> erase(const ebpf_cache_physical_key& key) noexcept override {
        errno = 0;
        if (bpf_map_delete_elem(map_fd_, &key) == 0)
            return {};
        return std::unexpected(current_error());
    }

private:
    int map_fd_; ///< File descriptor of the BPF cache hash map.
};

} // namespace

/// Create the production cache-map wrapper over the given BPF map fd.
std::unique_ptr<EbpfCacheMap> make_production_ebpf_cache_map(int map_fd) {
    return std::make_unique<ProductionEbpfCacheMap>(map_fd);
}

} // namespace shinku::backend::ebpf
