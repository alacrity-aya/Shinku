// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_backend.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_cache_store.h"
#include "backend/dpdk/dpdk_cleanup_tasks.h"
#include "backend/dpdk/dpdk_dns_packet.h"
#include "backend/dpdk/dpdk_eal.h"
#include "backend/dpdk/dpdk_error.h"
#include "backend/dpdk/dpdk_packet_path.h"
#include "backend/dpdk/dpdk_packet_pool.h"
#include "backend/dpdk/dpdk_pending_store.h"
#include "backend/dpdk/dpdk_port.h"
#include "backend/dpdk/dpdk_scheduler.h"
#include "config/config.h"

#include <array>
#include <cassert>
#include <chrono>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <rte_memory.h>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

/// Default interval between DPDK cache-cleanup sweeps until a config-bound value exists.
constexpr std::chrono::seconds kDefaultCacheCleanupInterval { 1 };

/// Translate a @ref DpdkError into a @ref BackendError with the given category.
std::unexpected<BackendError> dpdk_error(BackendErrorCode code, const DpdkError& error) {
    std::string message = std::format("DPDK {} failed", error.operation);
    if (!error.detail.empty())
        message += ": " + error.detail;
    if (error.cause.has_value())
        message += ": " + error.cause->message();
    return std::unexpected(BackendError { .code = code, .message = std::move(message), .cause = error.cause });
}

} // namespace

/// Adopt the EAL, ports, and pool; @p cache_config drives the cache and pending stores.
DpdkBackend::DpdkBackend(
    std::span<const std::string> eal_arguments,
    const config::CacheConfig& cache_config,
    std::unique_ptr<DpdkEal> eal,
    std::unique_ptr<DpdkPacketPool> packet_pool,
    std::unique_ptr<DpdkPort> client_port,
    std::unique_ptr<DpdkPort> service_port
):
    eal_arguments_(eal_arguments.begin(), eal_arguments.end()),
    cache_config_(cache_config),
    eal_(std::move(eal)),
    packet_pool_(std::move(packet_pool)),
    client_port_(std::move(client_port)),
    service_port_(std::move(service_port)) {
    assert(eal_ != nullptr);
    assert(packet_pool_ != nullptr);
    assert(client_port_ != nullptr);
    assert(service_port_ != nullptr);
}

DpdkBackend::~DpdkBackend() = default;

/// DPDK probe is a no-op; capability checks happen during @ref start.
std::expected<void, BackendError> DpdkBackend::probe() {
    return {};
}

/**
 * @brief Initialize EAL, ports, pool, stores, and the forwarding pipeline.
 *
 * Ordering matters: EAL first, then both ports are configured so their
 * descriptor counts can size the shared packet pool, queues are set up on the
 * EAL's main socket, and the ports are started. Only then are the cache and
 * pending stores, DNS policy, forwarders, cleanup tasks, and the cooperative
 * scheduler constructed over them.
 */
std::expected<void, BackendError> DpdkBackend::start() {
    spdlog::info("starting DPDK backend");
    if (auto result = eal_->initialize(eal_arguments_); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());

    auto client_descriptors = client_port_->configure();
    if (!client_descriptors)
        return dpdk_error(BackendErrorCode::StartFailed, client_descriptors.error());
    auto service_descriptors = service_port_->configure();
    if (!service_descriptors)
        return dpdk_error(BackendErrorCode::StartFailed, service_descriptors.error());

    const std::array descriptors { *client_descriptors, *service_descriptors };
    if (auto result = packet_pool_->create(descriptors, eal_->main_socket_id()); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());
    if (auto result = client_port_->setup_queues(eal_->main_socket_id()); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());
    if (auto result = service_port_->setup_queues(eal_->main_socket_id()); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());
    if (auto result = client_port_->start(); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());
    if (auto result = service_port_->start(); !result)
        return dpdk_error(BackendErrorCode::StartFailed, result.error());
    client_port_->log_link_state();
    service_port_->log_link_state();

    auto cache = DpdkCacheStore::create(cache_config_.max_entries(), cache_config_.max_response_bytes(), SOCKET_ID_ANY);
    if (!cache) {
        return std::unexpected(
            BackendError {
                .code = BackendErrorCode::StartFailed,
                .message = "DPDK cache store creation failed",
                .cause = cache.error().cause,
            }
        );
    }
    auto pending = DpdkPendingStore::create(cache_config_.max_pending_queries(), SOCKET_ID_ANY);
    if (!pending) {
        return std::unexpected(
            BackendError {
                .code = BackendErrorCode::StartFailed,
                .message = "DPDK pending store creation failed",
                .cause = pending.error(),
            }
        );
    }
    cache_store_ = std::move(*cache);
    pending_store_ = std::move(*pending);
    dns_policy_ =
        std::make_unique<cache::DnsPolicy>(cache_config_.max_response_bytes(), cache_config_.cache_negative());
    cache_context_ = std::make_unique<DpdkCacheContext>(DpdkCacheContext {
        .cache = *cache_store_,
        .pending = *pending_store_,
        .policy = *dns_policy_,
        .pending_timeout = cache_config_.pending_query_timeout(),
        // TODO: expose a DPDK-specific interval after the CLI/config boundary is settled.
        .cache_cleanup_interval = kDefaultCacheCleanupInterval,
    });

    client_path_ = std::make_unique<DpdkPacketForwarder>(
        *client_port_,
        *service_port_,
        DnsPacketDirection::Query,
        *cache_context_
    );
    service_path_ = std::make_unique<DpdkPacketForwarder>(
        *service_port_,
        *client_port_,
        DnsPacketDirection::Response,
        *cache_context_
    );
    cache_cleanup_task_ = std::make_unique<DpdkCacheCleanupTask>(*cache_context_);
    pending_cleanup_task_ = std::make_unique<DpdkPendingCleanupTask>(*cache_context_);
    scheduler_ = std::make_unique<DpdkCooperativeScheduler>(
        *client_path_,
        *service_path_,
        *cache_cleanup_task_,
        *pending_cleanup_task_
    );
    spdlog::info("DPDK backend started");
    return {};
}

/// Run one cooperative scheduling quantum over the client, service, cache, and pending tasks.
std::expected<void, BackendError> DpdkBackend::poll() {
    assert(scheduler_ != nullptr);
    return scheduler_->run_quantum();
}

/**
 * @brief Tear down the pipeline in reverse construction order.
 *
 * Destroys the scheduler and stores first (they reference the ports and EAL),
 * then closes the service and client ports. The packet pool and EAL are closed
 * only when no port still owns the resources, so ownership hand-off between
 * EAL, pool, and ports is released exactly once.
 */
std::expected<void, BackendError> DpdkBackend::stop() {
    scheduler_.reset();
    pending_cleanup_task_.reset();
    cache_cleanup_task_.reset();
    service_path_.reset();
    client_path_.reset();
    cache_context_.reset();
    dns_policy_.reset();
    pending_store_.reset();
    cache_store_.reset();

    std::optional<DpdkError> first_error;
    const auto record = [&first_error](const std::expected<void, DpdkError>& result) {
        if (!result && !first_error)
            first_error = result.error();
    };
    record(service_port_->close());
    record(client_port_->close());
    if (!service_port_->owns_resources() && !client_port_->owns_resources())
        record(packet_pool_->close());
    if (!service_port_->owns_resources() && !client_port_->owns_resources() && !packet_pool_->owns_resources())
        record(eal_->close());

    if (first_error)
        return dpdk_error(BackendErrorCode::StopFailed, *first_error);
    spdlog::info("DPDK backend stopped");
    return {};
}

} // namespace shinku::backend::dpdk
