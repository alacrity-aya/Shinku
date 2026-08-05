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

// Owns the background thread that alternates due Cache Store and Pending Query
// cleanup work between packet-ring polls. Held by EbpfBackend via unique_ptr so
// the backend header stays free of <thread>.
class CleanupWorker {
public:
    CleanupWorker() = default;
    ~CleanupWorker() = default;

    CleanupWorker(const CleanupWorker&) = delete;
    CleanupWorker& operator=(const CleanupWorker&) = delete;
    CleanupWorker(CleanupWorker&&) = delete;
    CleanupWorker& operator=(CleanupWorker&&) = delete;

    // Spawns the worker thread. Joining is implicit: destroying the worker
    // requests stop and joins the thread, so callers must tear down referenced
    // stores only after the worker is gone.
    [[nodiscard]] std::expected<void, std::error_code> start(
        cache::CacheStore& store,
        PendingQueryCleaner& pending,
        std::chrono::milliseconds cache_interval,
        std::chrono::nanoseconds pending_interval
    );

private:
    static void run(
        std::stop_token token,
        cache::CacheStore& store,
        PendingQueryCleaner& pending,
        std::chrono::milliseconds cache_interval,
        std::chrono::nanoseconds pending_interval
    ) noexcept;

    std::jthread thread;
};

} // namespace shinku::backend::ebpf
