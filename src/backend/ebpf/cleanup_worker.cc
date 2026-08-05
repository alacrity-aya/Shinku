// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cleanup_worker.h"

#include "backend/ebpf/cache/pending_query_cleaner.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <mutex>
#include <stop_token>
#include <system_error>
#include <utility>

namespace shinku::backend::ebpf {

std::expected<void, std::error_code> CleanupWorker::start(
    cache::CacheStore& store,
    PendingQueryCleaner& pending,
    std::chrono::milliseconds cache_interval,
    std::chrono::nanoseconds pending_interval
) {
    try {
        thread = std::jthread([&store, &pending, cache_interval, pending_interval](std::stop_token token) noexcept {
            run(std::move(token), store, pending, cache_interval, pending_interval);
        });
    } catch (const std::system_error& error) {
        return std::unexpected(error.code());
    }
    return {};
}

void CleanupWorker::run(
    std::stop_token token,
    cache::CacheStore& store,
    PendingQueryCleaner& pending,
    std::chrono::milliseconds cache_interval,
    std::chrono::nanoseconds pending_interval
) noexcept {
    std::mutex wait_mutex;
    std::condition_variable_any wake;
    auto next_cache = std::chrono::steady_clock::now() + cache_interval;
    auto next_pending = std::chrono::steady_clock::now() + pending_interval;
    bool cache_turn = true;

    while (!token.stop_requested()) {
        {
            std::unique_lock lock(wait_mutex);
            const auto deadline = std::min(next_cache, next_pending);
            const bool stopped =
                wake.wait_until(lock, token, deadline, [&token] { return token.stop_requested(); });
            if (stopped || token.stop_requested())
                break;
        }

        const auto current = std::chrono::steady_clock::now();
        const bool cache_due = current >= next_cache;
        const bool pending_due = current >= next_pending;
        const bool run_cache = cache_due && (!pending_due || cache_turn);
        cache_turn = !run_cache;
        const auto now = cache::boot_time();
        if (run_cache) {
            auto result = store.cleanup(now);
            next_cache = result && result->more_work ? std::chrono::steady_clock::now()
                                                     : std::chrono::steady_clock::now() + cache_interval;
        } else {
            auto result = pending.cleanup(now);
            next_pending = result && result->more_work ? std::chrono::steady_clock::now()
                                                       : std::chrono::steady_clock::now() + pending_interval;
        }
    }
}

} // namespace shinku::backend::ebpf
