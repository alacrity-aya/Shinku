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
#include <variant>

namespace shinku::backend {

std::expected<std::unique_ptr<Backend>, BackendError> make_backend(const config::Config& config) {
    if (const auto* ebpf_config = std::get_if<config::EbpfConfig>(&config.backend)) {
        return std::make_unique<ebpf::EbpfBackend>(
            *ebpf_config,
            config.cache,
            std::make_unique<ebpf::ProductionEbpfNativeSession>()
        );
    }

    return std::unexpected(BackendError {
        .code = BackendErrorCode::Unsupported,
        .message = "DPDK backend is not implemented",
        .cause = std::nullopt,
    });
}

} // namespace shinku::backend
