// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <chrono>
#include <expected>
#include <stop_token>
#include <system_error>
#include <thread>

namespace shinku::cache {
class CacheStore;
}

namespace shinku::backend::ebpf {

class PendingQueryCleaner;

/**
 * @brief Owns the background thread that sweeps cache and pending entries.
 *
 * Alternates due @ref cache::CacheStore and @ref PendingQueryCleaner cleanup
 * work between packet-ring polls. Held by @ref EbpfBackend via unique_ptr so
 * the backend header stays free of `std::thread`.
 */
class CleanupWorker {
public:
    CleanupWorker() = default;
    ~CleanupWorker() = default;

    CleanupWorker(const CleanupWorker&) = delete;
    CleanupWorker& operator=(const CleanupWorker&) = delete;
    CleanupWorker(CleanupWorker&&) = delete;
    CleanupWorker& operator=(CleanupWorker&&) = delete;

    /**
     * @brief Spawn the worker thread.
     *
     * @note Joining is implicit: destroying the worker requests stop and
     *       joins the thread, so callers must tear down referenced stores
     *       only after the worker is gone.
     *
     * @param store The cache store to sweep.
     * @param pending The pending-query cleaner to drive.
     * @param cache_interval Interval between cache cleanup sweeps.
     * @param pending_interval Interval between pending-query cleanup sweeps.
     * @return Void on success, or a std::error_code if the thread could not spawn.
     */
    [[nodiscard]] std::expected<void, std::error_code> start(
        cache::CacheStore& store,
        PendingQueryCleaner& pending,
        std::chrono::milliseconds cache_interval,
        std::chrono::nanoseconds pending_interval
    );

private:
    /// @brief Worker loop body, driven by @p token for cooperative cancellation.
    static void run(
        std::stop_token token,
        cache::CacheStore& store,
        PendingQueryCleaner& pending,
        std::chrono::milliseconds cache_interval,
        std::chrono::nanoseconds pending_interval
    ) noexcept;

    std::jthread thread; ///< The worker thread; stop requested on destruction.
};

} // namespace shinku::backend::ebpf
