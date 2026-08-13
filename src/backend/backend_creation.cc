// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_creation.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_backend.h"
#include "backend/dpdk/dpdk_native_session.h"
#include "backend/ebpf/ebpf_backend.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "config/config.h"

#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>

namespace shinku::backend {

std::expected<std::unique_ptr<Backend>, BackendError>
make_backend(const config::Config& config, std::span<const std::string> dpdk_arguments) {
    if (const auto* ebpf_config = std::get_if<config::EbpfConfig>(&config.backend)) {
        if (!dpdk_arguments.empty()) {
            return std::unexpected(BackendError {
                .code = BackendErrorCode::WrongConfig,
                .message = "DPDK EAL arguments were provided for the eBPF backend",
                .cause = std::nullopt,
            });
        }
        return std::make_unique<ebpf::EbpfBackend>(
            *ebpf_config,
            config.cache,
            std::make_unique<ebpf::ProductionEbpfNativeSession>()
        );
    }

    return std::make_unique<dpdk::DpdkBackend>(dpdk_arguments, std::make_unique<dpdk::ProductionDpdkNativeSession>());
}

} // namespace shinku::backend
