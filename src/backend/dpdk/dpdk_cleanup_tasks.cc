// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_cleanup_tasks.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_cache_store.h"
#include "backend/dpdk/dpdk_pending_store.h"
#include "backend/dpdk/dpdk_time.h"

#include <expected>
#include <spdlog/spdlog.h>

namespace shinku::backend::dpdk {

/// Run one bounded cache-cleanup sweep once the interval deadline has elapsed; on a clock
/// failure (warned once) or a failed sweep defer by one interval, and when the cache reports
/// more work reset the deadline to now so the next quantum continues the sweep immediately.
std::expected<void, BackendError> DpdkCacheCleanupTask::run() {
    const auto now = read_dpdk_boot_time();
    if (!now) {
        if (!context_.maintenance_time_warning_emitted) {
            spdlog::warn("DPDK cache cleanup skipped after a CLOCK_BOOTTIME read failure");
            context_.maintenance_time_warning_emitted = true;
        }
        return {};
    }
    if (!deadline_) {
        deadline_ = *now + context_.cache_cleanup_interval;
        return {};
    }
    if (*now < *deadline_)
        return {};
    auto result = context_.cache.cleanup(*now);
    if (!result) {
        if (!warning_emitted_) {
            spdlog::warn("DPDK cache cleanup failed and will retry");
            warning_emitted_ = true;
        }
        deadline_ = *now + context_.cache_cleanup_interval;
        return {};
    }
    warning_emitted_ = false;
    deadline_ = result->more_work ? *now : *now + context_.cache_cleanup_interval;
    return {};
}

/// Run one bounded pending-query sweep once the half-timeout deadline has elapsed, deferring
/// by that same interval on failure (warned once) and continuing immediately while more work
/// remains.
std::expected<void, BackendError> DpdkPendingCleanupTask::run() {
    const auto now = read_dpdk_boot_time();
    if (!now) {
        if (!context_.maintenance_time_warning_emitted) {
            spdlog::warn("DPDK pending cleanup skipped after a CLOCK_BOOTTIME read failure");
            context_.maintenance_time_warning_emitted = true;
        }
        return {};
    }
    const auto cleanup_interval = context_.pending_timeout / 2;
    if (!deadline_) {
        deadline_ = *now + cleanup_interval;
        return {};
    }
    if (*now < *deadline_)
        return {};
    auto result = context_.pending.cleanup(*now, context_.pending_timeout);
    if (!result) {
        if (!warning_emitted_) {
            spdlog::warn("DPDK pending cleanup failed and will retry");
            warning_emitted_ = true;
        }
        deadline_ = *now + cleanup_interval;
        return {};
    }
    warning_emitted_ = false;
    deadline_ = result->more_work ? *now : *now + cleanup_interval;
    return {};
}

} // namespace shinku::backend::dpdk
