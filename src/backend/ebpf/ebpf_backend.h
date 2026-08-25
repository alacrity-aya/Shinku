// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend.h"
#include "backend/ebpf/cache/correlated_dns_event_consumer.h"
#include "backend/ebpf/cache/ebpf_cache_store.h"
#include "backend/ebpf/cache/pending_query_cleaner.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "cache/dns_policy.h"
#include "config/config.h"

#include <memory>

namespace shinku::backend::ebpf {

class CleanupWorker;

/**
 * @brief eBPF-backed @ref Backend driving the XDP/TC packet path.
 *
 * Owns the native libbpf session, the eBPF cache store, the pending-query
 * cleaner, the DNS policy, the correlated-DNS event consumer, and the
 * background cleanup worker that sweeps expired cache and pending entries
 * between packet-ring polls.
 */
class EbpfBackend final: public Backend {
public:
    /// @brief Construct the eBPF backend from its config and native session.
    /// @param ebpf_config The validated eBPF backend configuration.
    /// @param cache_config The backend-neutral cache configuration.
    /// @param native_session The libbpf native session owning BPF resources.
    EbpfBackend(
        config::EbpfConfig ebpf_config,
        config::CacheConfig cache_config,
        std::unique_ptr<EbpfNativeSession> native_session
    );
    ~EbpfBackend() override;

protected:
    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<void, BackendError> poll() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    config::EbpfConfig config_; ///< Validated eBPF backend configuration.
    config::CacheConfig cache_config_; ///< Backend-neutral cache configuration.
    std::unique_ptr<EbpfNativeSession> native_session_; ///< libbpf session owning BPF resources.
    std::unique_ptr<EbpfCacheStore> cache_store_; ///< eBPF map-backed cache store.
    std::unique_ptr<PendingQueryCleaner> pending_cleaner_; ///< Pending-query cleaner.
    std::unique_ptr<cache::DnsPolicy> dns_policy_; ///< DNS cache policy.
    std::unique_ptr<CorrelatedDnsEventConsumer> event_consumer_; ///< Correlated-DNS ring consumer.
    std::unique_ptr<CleanupWorker> cleanup_worker_; ///< Background cleanup worker thread.
};

} // namespace shinku::backend::ebpf
