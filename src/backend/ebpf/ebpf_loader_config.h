// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace shinku::backend::ebpf {

struct EbpfLoaderConfig {
    std::string iface;
    uint32_t arena_pages;
    uint32_t cleanup_interval_ms;
};

} // namespace shinku::backend::ebpf
