// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <variant>

namespace shinku::config {

enum class ConfigValidationError : uint8_t {
    EbpfCleanupIntervalNotPositive,
    EbpfPacketPollTimeoutOutOfRange,
    CacheMaxEntriesZero,
    CacheMaxResponseBytesOutOfRange,
    CacheMaxPendingQueriesZero,
    CachePendingQueryTimeoutOutOfRange,
};

class EbpfConfig {
public:
    static constexpr std::chrono::milliseconds kDefaultPacketPollTimeout { 100 };
    static constexpr std::chrono::milliseconds kMinimumPacketPollTimeout { 1 };
    static constexpr std::chrono::milliseconds kMaximumPacketPollTimeout { 1000 };

    struct Params {
        std::string iface;
        std::chrono::milliseconds cleanup_interval;
        std::chrono::milliseconds packet_poll_timeout { kDefaultPacketPollTimeout };
    };

    [[nodiscard]] static std::expected<EbpfConfig, ConfigValidationError> create(Params params) noexcept {
        if (params.cleanup_interval <= std::chrono::milliseconds::zero())
            return std::unexpected(ConfigValidationError::EbpfCleanupIntervalNotPositive);
        if (params.packet_poll_timeout < kMinimumPacketPollTimeout
            || params.packet_poll_timeout > kMaximumPacketPollTimeout)
        {
            return std::unexpected(ConfigValidationError::EbpfPacketPollTimeoutOutOfRange);
        }

        return EbpfConfig(std::move(params));
    }

    [[nodiscard]] const std::string& iface() const noexcept {
        return iface_;
    }
    [[nodiscard]] std::chrono::milliseconds cleanup_interval() const noexcept {
        return cleanup_interval_;
    }
    [[nodiscard]] std::chrono::milliseconds packet_poll_timeout() const noexcept {
        return packet_poll_timeout_;
    }

private:
    explicit EbpfConfig(Params params) noexcept:
        iface_(std::move(params.iface)),
        cleanup_interval_(params.cleanup_interval),
        packet_poll_timeout_(params.packet_poll_timeout) {}

    std::string iface_;
    std::chrono::milliseconds cleanup_interval_;
    std::chrono::milliseconds packet_poll_timeout_;
};

struct DpdkConfig {
    uint16_t client_port;
    uint16_t server_port;
};

class CacheConfig {
public:
    static constexpr uint32_t kMinimumResponseBytes = 128;
    static constexpr uint32_t kMaximumResponseBytes = 512;
    static constexpr std::chrono::milliseconds kMinimumPendingQueryTimeout { 100 };
    static constexpr std::chrono::milliseconds kMaximumPendingQueryTimeout { 10'000 };

    struct Params {
        uint32_t max_entries;
        uint32_t max_response_bytes;
        bool cache_negative;
        uint32_t max_pending_queries;
        std::chrono::milliseconds pending_query_timeout;
    };

    [[nodiscard]] static std::expected<CacheConfig, ConfigValidationError> create(Params params) noexcept {
        if (params.max_entries == 0)
            return std::unexpected(ConfigValidationError::CacheMaxEntriesZero);
        if (params.max_response_bytes < kMinimumResponseBytes || params.max_response_bytes > kMaximumResponseBytes)
            return std::unexpected(ConfigValidationError::CacheMaxResponseBytesOutOfRange);
        if (params.max_pending_queries == 0)
            return std::unexpected(ConfigValidationError::CacheMaxPendingQueriesZero);
        if (params.pending_query_timeout < kMinimumPendingQueryTimeout
            || params.pending_query_timeout > kMaximumPendingQueryTimeout)
        {
            return std::unexpected(ConfigValidationError::CachePendingQueryTimeoutOutOfRange);
        }

        return CacheConfig(params);
    }

    [[nodiscard]] uint32_t max_entries() const noexcept {
        return max_entries_;
    }
    [[nodiscard]] uint32_t max_response_bytes() const noexcept {
        return max_response_bytes_;
    }
    [[nodiscard]] bool cache_negative() const noexcept {
        return cache_negative_;
    }
    [[nodiscard]] uint32_t max_pending_queries() const noexcept {
        return max_pending_queries_;
    }
    [[nodiscard]] std::chrono::milliseconds pending_query_timeout() const noexcept {
        return pending_query_timeout_;
    }

private:
    explicit CacheConfig(Params params) noexcept:
        max_entries_(params.max_entries),
        max_response_bytes_(params.max_response_bytes),
        cache_negative_(params.cache_negative),
        max_pending_queries_(params.max_pending_queries),
        pending_query_timeout_(params.pending_query_timeout) {}

    uint32_t max_entries_;
    uint32_t max_response_bytes_;
    bool cache_negative_;
    uint32_t max_pending_queries_;
    std::chrono::milliseconds pending_query_timeout_;
};

using BackendConfig = std::variant<EbpfConfig, DpdkConfig>;

struct Config {
    BackendConfig backend;
    CacheConfig cache;
};

} // namespace shinku::config
