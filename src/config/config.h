// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <utility>
#include <variant>

namespace shinku::config {

/// Failure codes returned when validating configuration parameters.
enum class ConfigValidationError : uint8_t {
    EbpfCleanupIntervalNotPositive, ///< The eBPF cleanup interval was zero or negative.
    EbpfPacketPollTimeoutOutOfRange, ///< The eBPF packet poll timeout was outside its allowed range.
    CacheMaxEntriesZero, ///< The cache max-entries count was zero.
    CacheMaxResponseBytesOutOfRange, ///< The max response byte limit was outside its allowed range.
    CacheMaxPendingQueriesZero, ///< The max pending-queries count was zero.
    CachePendingQueryTimeoutOutOfRange, ///< The pending-query timeout was outside its allowed range.
};

/**
 * @brief Validated eBPF backend configuration.
 *
 * Constructed via @ref create, which checks every field against its bounds so
 * that a constructed EbpfConfig is guaranteed usable.
 */
class EbpfConfig {
public:
    static constexpr std::chrono::milliseconds kDefaultPacketPollTimeout { 100 }; ///< Default poll timeout (100 ms).
    static constexpr std::chrono::milliseconds kMinimumPacketPollTimeout { 1 }; ///< Minimum poll timeout (1 ms).
    static constexpr std::chrono::milliseconds kMaximumPacketPollTimeout { 1000 }; ///< Maximum poll timeout (1000 ms).

    /// Input parameters for constructing an @ref EbpfConfig.
    struct Params {
        std::string iface; ///< Network interface to attach the XDP/TC programs to.
        std::chrono::milliseconds cleanup_interval; ///< Interval between cache cleanup sweeps.
        std::chrono::milliseconds packet_poll_timeout { kDefaultPacketPollTimeout }; ///< Per-iteration packet poll timeout.
    };

    /**
     * @brief Construct an EbpfConfig, validating each parameter.
     * @param params The parameters to validate and adopt.
     * @return The config, or a @ref ConfigValidationError describing the first invalid field.
     */
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

    /// @return The configured network interface name.
    [[nodiscard]] const std::string& iface() const noexcept {
        return iface_;
    }
    /// @return The configured cleanup interval.
    [[nodiscard]] std::chrono::milliseconds cleanup_interval() const noexcept {
        return cleanup_interval_;
    }
    /// @return The configured packet poll timeout.
    [[nodiscard]] std::chrono::milliseconds packet_poll_timeout() const noexcept {
        return packet_poll_timeout_;
    }

private:
    explicit EbpfConfig(Params params) noexcept:
        iface_(std::move(params.iface)),
        cleanup_interval_(params.cleanup_interval),
        packet_poll_timeout_(params.packet_poll_timeout) {}

    std::string iface_; ///< Network interface name.
    std::chrono::milliseconds cleanup_interval_; ///< Cleanup sweep interval.
    std::chrono::milliseconds packet_poll_timeout_; ///< Packet poll timeout.
};

/// Tag type selecting the DPDK backend in @ref BackendConfig.
struct DpdkBackendSelection {};

/**
 * @brief Validated cache configuration shared by all backends.
 *
 * Constructed via @ref create, which checks every field against its bounds so
 * that a constructed CacheConfig is guaranteed usable.
 */
class CacheConfig {
public:
    static constexpr uint32_t kMinimumResponseBytes = 128; ///< Minimum max-response-bytes value.
    static constexpr uint32_t kMaximumResponseBytes = 512; ///< Maximum max-response-bytes value.
    static constexpr std::chrono::milliseconds kMinimumPendingQueryTimeout { 100 }; ///< Minimum pending-query timeout.
    static constexpr std::chrono::milliseconds kMaximumPendingQueryTimeout { 10'000 }; ///< Maximum pending-query timeout.

    /// Input parameters for constructing a @ref CacheConfig.
    struct Params {
        uint32_t max_entries; ///< Maximum number of cache entries.
        uint32_t max_response_bytes; ///< Maximum stored response size in bytes.
        bool cache_negative; ///< Whether negative responses may be cached.
        uint32_t max_pending_queries; ///< Maximum number of outstanding pending queries.
        std::chrono::milliseconds pending_query_timeout; ///< How long a pending query may remain unresolved.
    };

    /**
     * @brief Construct a CacheConfig, validating each parameter.
     * @param params The parameters to validate and adopt.
     * @return The config, or a @ref ConfigValidationError describing the first invalid field.
     */
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

    /// @return The maximum number of cache entries.
    [[nodiscard]] uint32_t max_entries() const noexcept {
        return max_entries_;
    }
    /// @return The maximum stored response size in bytes.
    [[nodiscard]] uint32_t max_response_bytes() const noexcept {
        return max_response_bytes_;
    }
    /// @return Whether negative responses may be cached.
    [[nodiscard]] bool cache_negative() const noexcept {
        return cache_negative_;
    }
    /// @return The maximum number of outstanding pending queries.
    [[nodiscard]] uint32_t max_pending_queries() const noexcept {
        return max_pending_queries_;
    }
    /// @return How long a pending query may remain unresolved.
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

    uint32_t max_entries_; ///< Maximum cache entry count.
    uint32_t max_response_bytes_; ///< Maximum response size in bytes.
    bool cache_negative_; ///< Whether negative caching is allowed.
    uint32_t max_pending_queries_; ///< Maximum pending-query count.
    std::chrono::milliseconds pending_query_timeout_; ///< Pending-query timeout.
};

/// Variant selecting either an eBPF backend config or the DPDK backend.
using BackendConfig = std::variant<EbpfConfig, DpdkBackendSelection>;

/// The fully resolved application configuration: backend selection plus cache config.
struct Config {
    BackendConfig backend; ///< Which backend to construct and its parameters.
    CacheConfig cache; ///< Backend-neutral cache configuration.
};

} // namespace shinku::config
