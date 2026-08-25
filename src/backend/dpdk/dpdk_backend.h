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

/**
 * @brief DPDK-backed @ref Backend implementing the cooperative cache data path.
 *
 * Owns the EAL, packet pool, client/service ports, cache and pending stores,
 * the DNS policy, and the cooperative scheduler that drives the four poll
 * tasks (client path, service path, cache cleanup, pending cleanup) on a
 * single lcore.
 */
class DpdkBackend final: public Backend {
public:
    /**
     * @brief Construct a DPDK backend from its pre-assembled components.
     *
     * @param eal_arguments EAL arguments (retained for diagnostics).
     * @param cache_config Backend-neutral cache configuration.
     * @param eal The EAL owner.
     * @param packet_pool The shared packet pool.
     * @param client_port The client-facing Ethernet port.
     * @param service_port The service-facing Ethernet port.
     */
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
    std::vector<std::string> eal_arguments_; ///< Retained EAL arguments for diagnostics.
    config::CacheConfig cache_config_; ///< Backend-neutral cache configuration.
    std::unique_ptr<DpdkEal> eal_; ///< The EAL owner.
    std::unique_ptr<DpdkPacketPool> packet_pool_; ///< The shared packet pool.
    std::unique_ptr<DpdkPort> client_port_; ///< The client-facing Ethernet port.
    std::unique_ptr<DpdkPort> service_port_; ///< The service-facing Ethernet port.
    std::unique_ptr<DpdkCacheStore> cache_store_; ///< The cache store.
    std::unique_ptr<DpdkPendingStore> pending_store_; ///< The pending-query store.
    std::unique_ptr<cache::DnsPolicy> dns_policy_; ///< The DNS cache policy.
    std::unique_ptr<DpdkCacheContext> cache_context_; ///< Shared cache/pending context.
    std::unique_ptr<DpdkPacketForwarder> client_path_; ///< Client-facing forwarding task.
    std::unique_ptr<DpdkPacketForwarder> service_path_; ///< Service-facing forwarding task.
    std::unique_ptr<DpdkCooperativeScheduler> scheduler_; ///< Single-lcore cooperative scheduler.
    std::unique_ptr<DpdkCacheCleanupTask> cache_cleanup_task_; ///< Cache cleanup task.
    std::unique_ptr<DpdkPendingCleanupTask> pending_cleanup_task_; ///< Pending-query cleanup task.
};

} // namespace shinku::backend::dpdk
