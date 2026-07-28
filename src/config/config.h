// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <variant>

namespace shinku::config {

enum class BackendKind : uint8_t {
    Ebpf,
    Dpdk,
};

struct EbpfConfig {
    std::string iface;
    uint32_t arena_pages;
    std::chrono::milliseconds cleanup_interval;
    std::chrono::milliseconds packet_poll_timeout { 100 };
};

struct DpdkConfig {
    uint16_t client_port;
    uint16_t server_port;
};

struct CacheConfig {
    uint32_t max_entries;
    uint32_t max_response_bytes;
    bool cache_negative;
    uint32_t max_pending_queries;
    std::chrono::milliseconds pending_query_timeout;
};

using BackendConfig = std::variant<EbpfConfig, DpdkConfig>;

struct Config {
    BackendKind backend;
    BackendConfig backend_config;
    CacheConfig cache;
};

} // namespace shinku::config
