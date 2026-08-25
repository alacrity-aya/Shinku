// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#include <expected>
#include <system_error>

namespace shinku::backend::ebpf {

/**
 * @brief Generate a fresh random cache secret.
 *
 * The secret salts the physical-key fingerprint so that observers without the
 * secret cannot predict key placements. It is generated once at backend
 * startup and held for the lifetime of the cache store.
 *
 * @return A freshly generated @ref ebpf_cache_secret, or a std::error_code if the system RNG failed.
 */
[[nodiscard]] std::expected<ebpf_cache_secret, std::error_code> make_ebpf_cache_secret() noexcept;

} // namespace shinku::backend::ebpf
