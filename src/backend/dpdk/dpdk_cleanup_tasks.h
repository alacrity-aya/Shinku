// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_packet_path.h"

#include <optional>

namespace shinku::backend::dpdk {

/**
 * @brief Cooperative task that sweeps expired cache entries on a schedule.
 *
 * Runs the cache cleanup loop at the interval configured in @ref DpdkCacheContext,
 * bounded per quantum so a single sweep cannot starve the other poll tasks.
 */
class DpdkCacheCleanupTask final: public DpdkPollTask {
public:
    /// @brief Construct a cache cleanup task bound to @p context.
    explicit DpdkCacheCleanupTask(DpdkCacheContext& context) noexcept: context_(context) {}
    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    DpdkCacheContext& context_; ///< Shared cache/pending context.
    std::optional<cache::CacheTime> deadline_; ///< Next time a cleanup sweep is due.
    bool warning_emitted_ { false }; ///< True once a clock-time warning has been logged.
};

/**
 * @brief Cooperative task that reaps stale pending-query entries on a schedule.
 *
 * Runs the pending-query cleanup loop using the timeout configured in @ref
 * DpdkCacheContext, bounded per quantum so a single sweep cannot starve the
 * other poll tasks.
 */
class DpdkPendingCleanupTask final: public DpdkPollTask {
public:
    /// @brief Construct a pending cleanup task bound to @p context.
    explicit DpdkPendingCleanupTask(DpdkCacheContext& context) noexcept: context_(context) {}
    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    DpdkCacheContext& context_; ///< Shared cache/pending context.
    std::optional<cache::CacheTime> deadline_; ///< Next time a pending sweep is due.
    bool warning_emitted_ { false }; ///< True once a clock-time warning has been logged.
};

} // namespace shinku::backend::dpdk
