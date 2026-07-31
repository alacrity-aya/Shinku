// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_secret.h"

#include <cerrno>
#include <cstddef>
#include <expected>
#include <span>
#include <sys/random.h>
#include <sys/types.h>
#include <system_error>

namespace shinku::backend::ebpf {

std::expected<ebpf_cache_secret, std::error_code> make_ebpf_cache_secret() noexcept {
    ebpf_cache_secret secret {};
    auto remaining = std::as_writable_bytes(std::span(&secret, 1));
    while (!remaining.empty()) {
        errno = 0;
        const auto read = getrandom(remaining.data(), remaining.size(), 0);
        if (read > 0) {
            remaining = remaining.subspan(static_cast<size_t>(read));
            continue;
        }
        if (read < 0 && errno == EINTR)
            continue;
        return std::unexpected(std::error_code { errno == 0 ? EIO : errno, std::generic_category() });
    }
    return secret;
}

} // namespace shinku::backend::ebpf
