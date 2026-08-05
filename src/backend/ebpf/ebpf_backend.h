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

class EbpfBackend final: public Backend {
public:
    EbpfBackend(
        config::EbpfConfig ebpf_config,
        config::CacheConfig cache_config,
        std::unique_ptr<EbpfNativeSession> native_session
    );
    ~EbpfBackend() override;

protected:
    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<PollStatus, BackendError> poll() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    config::EbpfConfig config_;
    config::CacheConfig cache_config_;
    std::unique_ptr<EbpfNativeSession> native_session_;
    std::unique_ptr<EbpfCacheStore> cache_store_;
    std::unique_ptr<PendingQueryCleaner> pending_cleaner_;
    std::unique_ptr<cache::DnsPolicy> dns_policy_;
    std::unique_ptr<CorrelatedDnsEventConsumer> event_consumer_;
    std::unique_ptr<CleanupWorker> cleanup_worker_;
};

} // namespace shinku::backend::ebpf
