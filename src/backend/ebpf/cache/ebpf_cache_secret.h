// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#include <expected>
#include <system_error>

namespace shinku::backend::ebpf {

[[nodiscard]] std::expected<ebpf_cache_secret, std::error_code> make_ebpf_cache_secret() noexcept;

} // namespace shinku::backend::ebpf
