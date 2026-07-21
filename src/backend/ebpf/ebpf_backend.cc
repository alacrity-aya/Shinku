// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_backend.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/ebpf/ebpf_loader_ops.h"
#include "config/config.h"
#include "core/loader.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace shinku::backend::ebpf {
namespace {

BackendError
make_error(BackendErrorCode code, std::string message, std::optional<std::error_code> cause = std::nullopt) {
    return BackendError {
        .code = code,
        .message = std::move(message),
        .cause = cause,
    };
}

BackendError probe_operation_error(std::string_view operation, std::error_code cause) {
    return make_error(
        BackendErrorCode::ProbeFailed,
        std::format("eBPF {} probe failed: {}", operation, cause.message()),
        cause
    );
}

std::optional<std::error_code> explicit_negative_error(int result) {
    if (result >= 0)
        return std::nullopt;
    return std::error_code(-result, std::generic_category());
}

} // namespace

EbpfBackend::EbpfBackend(
    config::EbpfConfig ebpf_config,
    [[maybe_unused]] config::CacheConfig cache_config,
    const EbpfLoaderOps& ops,
    void* ops_context
):
    loader_config_ {
        .iface = std::move(ebpf_config.iface),
        .arena_pages = ebpf_config.arena_pages,
        .cleanup_interval_ms = static_cast<uint32_t>(ebpf_config.cleanup_interval.count()),
    },
    ops_(&ops),
    ops_context_(ops_context),
    bpf_context_(std::make_unique<bpf_ctx>()) {}

EbpfBackend::~EbpfBackend() = default;

std::expected<void, BackendError> EbpfBackend::probe() {
    auto privileges = ops_->has_required_privileges(ops_context_);
    if (!privileges)
        return std::unexpected(probe_operation_error("privilege", privileges.error()));
    if (!*privileges) {
        return std::unexpected(make_error(
            BackendErrorCode::PermissionDenied,
            "eBPF backend requires root or effective CAP_BPF, CAP_NET_ADMIN, and CAP_SYS_ADMIN"
        ));
    }

    auto interface = ops_->interface_exists(ops_context_, loader_config_.iface);
    if (!interface)
        return std::unexpected(probe_operation_error("interface", interface.error()));
    if (!*interface) {
        return std::unexpected(make_error(
            BackendErrorCode::WrongConfig,
            std::format("eBPF interface does not exist: {}", loader_config_.iface)
        ));
    }

    auto arena = ops_->arena_supported(ops_context_);
    if (!arena)
        return std::unexpected(probe_operation_error("BPF arena", arena.error()));
    if (!*arena) {
        return std::unexpected(make_error(BackendErrorCode::Unsupported, "host kernel does not support BPF arena maps")
        );
    }

    return {};
}

std::expected<void, BackendError> EbpfBackend::start() {
    if (loader_resources_active_) {
        return std::unexpected(
            make_error(BackendErrorCode::InvalidState, "cannot start eBPF backend while loader resources are active")
        );
    }

    const int setup_result = ops_->setup(ops_context_, bpf_context_.get(), loader_config_);
    if (setup_result != 0) {
        return std::unexpected(
            make_error(BackendErrorCode::StartFailed, std::format("eBPF loader setup failed: {}", setup_result))
        );
    }
    loader_resources_active_ = true;

    const int cleanup_thread_result =
        ops_->start_cleanup_thread(ops_context_, bpf_context_.get(), loader_config_.cleanup_interval_ms);
    if (cleanup_thread_result != 0) {
        return std::unexpected(make_error(
            BackendErrorCode::StartFailed,
            std::format("eBPF cleanup thread startup failed: {}", cleanup_thread_result),
            explicit_negative_error(cleanup_thread_result)
        ));
    }

    return {};
}

std::expected<PollStatus, BackendError> EbpfBackend::poll_once() {
    if (!loader_resources_active_) {
        return std::unexpected(
            make_error(BackendErrorCode::InvalidState, "cannot poll eBPF backend without active loader resources")
        );
    }

    const int log_result = ops_->poll_log_ring(ops_context_, bpf_context_.get(), 100);
    if (log_result == -EINTR)
        return PollStatus::NoWork;
    // This best-effort warning must not introduce an exception path into polling.
    if (log_result < 0)
        std::fprintf(stderr, "warning: eBPF log ring poll failed: %d (continuing)\n", log_result); // NOLINT

    const int packet_result = ops_->poll_packet_ring(ops_context_, bpf_context_.get(), 100);
    if (packet_result == -EINTR)
        return PollStatus::NoWork;
    if (packet_result < 0) {
        return std::unexpected(make_error(
            BackendErrorCode::PollFailed,
            std::format("eBPF packet ring poll failed: {}", packet_result),
            explicit_negative_error(packet_result)
        ));
    }

    return log_result > 0 || packet_result > 0 ? PollStatus::WorkDone : PollStatus::NoWork;
}

std::expected<void, BackendError> EbpfBackend::stop() {
    if (!loader_resources_active_)
        return {};

    ops_->cleanup(ops_context_, bpf_context_.get());
    loader_resources_active_ = false;
    return {};
}

} // namespace shinku::backend::ebpf
