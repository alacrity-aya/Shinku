// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_creation.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_backend.h"
#include "backend/dpdk/dpdk_eal.h"
#include "backend/dpdk/dpdk_packet_pool.h"
#include "backend/dpdk/dpdk_port.h"
#include "backend/ebpf/ebpf_backend.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "config/config.h"

#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>

namespace shinku::backend {

/// Builds the configured backend, wiring production EAL, packet pool, and ports for the DPDK path.
std::expected<std::unique_ptr<Backend>, BackendError>
make_backend(const config::Config& config, std::span<const std::string> dpdk_arguments) {
    if (const auto* ebpf_config = std::get_if<config::EbpfConfig>(&config.backend)) {
        if (!dpdk_arguments.empty()) {
            return std::unexpected(
                BackendError {
                    .code = BackendErrorCode::WrongConfig,
                    .message = "DPDK EAL arguments were provided for the eBPF backend",
                    .cause = std::nullopt,
                }
            );
        }
        return std::make_unique<ebpf::EbpfBackend>(
            *ebpf_config,
            config.cache,
            std::make_unique<ebpf::ProductionEbpfNativeSession>()
        );
    }

    auto eal = std::make_unique<dpdk::ProductionDpdkEal>();
    auto packet_pool = std::make_unique<dpdk::ProductionDpdkPacketPool>(*eal);
    auto client_port = std::make_unique<dpdk::ProductionDpdkPort>(0, "client Port ID 0", *eal, *packet_pool);
    auto service_port = std::make_unique<dpdk::ProductionDpdkPort>(1, "service Port ID 1", *eal, *packet_pool);
    return std::make_unique<dpdk::DpdkBackend>(
        dpdk_arguments,
        config.cache,
        std::move(eal),
        std::move(packet_pool),
        std::move(client_port),
        std::move(service_port)
    );
}

} // namespace shinku::backend
