// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend.h"
#include "config/config.h"
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace shinku::cache {
class DnsPolicy;
}

namespace shinku::backend::dpdk {

class DpdkCooperativeScheduler;
class DpdkEal;
class DpdkPacketPool;
class DpdkPort;
class DpdkPacketForwarder;
class DpdkCacheStore;
class DpdkPendingStore;
class DpdkCacheCleanupTask;
class DpdkPendingCleanupTask;
struct DpdkCacheContext;

class DpdkBackend final: public Backend {
public:
    DpdkBackend(
        std::span<const std::string> eal_arguments,
        const config::CacheConfig& cache_config,
        std::unique_ptr<DpdkEal> eal,
        std::unique_ptr<DpdkPacketPool> packet_pool,
        std::unique_ptr<DpdkPort> client_port,
        std::unique_ptr<DpdkPort> service_port
    );
    ~DpdkBackend() override;

protected:
    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<void, BackendError> poll() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    std::vector<std::string> eal_arguments_;
    config::CacheConfig cache_config_;
    std::unique_ptr<DpdkEal> eal_;
    std::unique_ptr<DpdkPacketPool> packet_pool_;
    std::unique_ptr<DpdkPort> client_port_;
    std::unique_ptr<DpdkPort> service_port_;
    std::unique_ptr<DpdkCacheStore> cache_store_;
    std::unique_ptr<DpdkPendingStore> pending_store_;
    std::unique_ptr<cache::DnsPolicy> dns_policy_;
    std::unique_ptr<DpdkCacheContext> cache_context_;
    std::unique_ptr<DpdkPacketForwarder> client_path_;
    std::unique_ptr<DpdkPacketForwarder> service_path_;
    std::unique_ptr<DpdkCooperativeScheduler> scheduler_;
    std::unique_ptr<DpdkCacheCleanupTask> cache_cleanup_task_;
    std::unique_ptr<DpdkPendingCleanupTask> pending_cleanup_task_;
};

} // namespace shinku::backend::dpdk
