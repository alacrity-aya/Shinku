// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_creation.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/ebpf/ebpf_backend.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "config/config.h"

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace shinku::backend {
namespace {

std::unexpected<BackendError> wrong_config(std::string message) {
    return std::unexpected(
        BackendError {
            .code = BackendErrorCode::WrongConfig,
            .message = std::move(message),
            .cause = std::nullopt,
        }
    );
}

} // namespace

std::expected<std::unique_ptr<Backend>, BackendError> make_backend(const config::Config& config) {
    switch (config.backend) {
        case config::BackendKind::Ebpf: {
            const auto* ebpf_config = std::get_if<config::EbpfConfig>(&config.backend_config);
            if (ebpf_config == nullptr)
                return wrong_config("selected eBPF backend does not match backend_config");

            return std::make_unique<ebpf::EbpfBackend>(
                *ebpf_config,
                config.cache,
                std::make_unique<ebpf::ProductionEbpfNativeSession>()
            );
        }
        case config::BackendKind::Dpdk:
            if (!std::holds_alternative<config::DpdkConfig>(config.backend_config))
                return wrong_config("selected DPDK backend does not match backend_config");
            return std::unexpected(
                BackendError {
                    .code = BackendErrorCode::Unsupported,
                    .message = "DPDK backend is not implemented",
                    .cause = std::nullopt,
                }
            );
    }

    return wrong_config("config contains an unknown backend kind");
}

} // namespace shinku::backend
