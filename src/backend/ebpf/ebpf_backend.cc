// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_backend.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/ebpf/cache/ebpf_cache_secret.h"
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "backend/ebpf/cleanup_worker.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "cache/cache_time.h"
#include "config/config.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace shinku::backend::ebpf {
namespace {

constexpr int kAttachAttempts = 5;
constexpr auto kAttachBaseDelay = std::chrono::milliseconds(50);
constexpr auto kAttachMaxDelay = std::chrono::milliseconds(800);

std::unexpected<BackendError>
make_error(BackendErrorCode code, std::string message, std::optional<std::error_code> cause = std::nullopt) {
    return std::unexpected(
        BackendError {
            .code = code,
            .message = std::move(message),
            .cause = cause,
        }
    );
}

std::unexpected<BackendError>
operation_error(BackendErrorCode code, std::string_view operation, std::error_code cause) {
    return make_error(code, std::format("eBPF {} failed: {}", operation, cause.message()), cause);
}

std::chrono::milliseconds retry_delay(int attempt) {
    return std::min(kAttachBaseDelay * (1 << attempt), kAttachMaxDelay);
}

bool is_interrupted(std::error_code error) {
    return error == std::errc::interrupted;
}

bool is_tcx_unsupported(std::error_code error) {
    return error == std::errc::operation_not_supported || error == std::errc::invalid_argument
        || error == std::errc::function_not_supported;
}

} // namespace

EbpfBackend::EbpfBackend(
    config::EbpfConfig ebpf_config,
    config::CacheConfig cache_config,
    std::unique_ptr<EbpfNativeSession> native_session
):
    config_(std::move(ebpf_config)),
    cache_config_(cache_config),
    native_session_(std::move(native_session)) {}

EbpfBackend::~EbpfBackend() = default;

std::expected<void, BackendError> EbpfBackend::probe() {
    auto privileges = native_session_->has_required_privileges();
    if (!privileges)
        return operation_error(BackendErrorCode::ProbeFailed, "privilege probe", privileges.error());
    if (!*privileges) {
        return make_error(
            BackendErrorCode::PermissionDenied,
            "eBPF backend requires root or effective CAP_BPF, CAP_NET_ADMIN, and CAP_SYS_ADMIN"
        );
    }

    auto interface = native_session_->interface_exists(config_.iface());
    if (!interface)
        return operation_error(BackendErrorCode::ProbeFailed, "interface probe", interface.error());
    if (!*interface) {
        return make_error(
            BackendErrorCode::WrongConfig,
            std::format("eBPF interface does not exist: {}", config_.iface())
        );
    }

    auto arena = native_session_->arena_supported();
    if (!arena) {
        if (arena.error() == std::errc::operation_not_supported)
            return make_error(BackendErrorCode::Unsupported, "host kernel does not support BPF arena maps");
        return operation_error(BackendErrorCode::ProbeFailed, "BPF arena probe", arena.error());
    }
    if (!*arena)
        return make_error(BackendErrorCode::Unsupported, "host kernel does not support BPF arena maps");
    return {};
}

std::expected<void, BackendError> EbpfBackend::start() {
    auto ifindex = native_session_->interface_index(config_.iface());
    if (!ifindex)
        return operation_error(BackendErrorCode::StartFailed, "interface lookup", ifindex.error());

    errno = 0;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        const auto cause =
            errno == 0 ? std::make_error_code(std::errc::io_error) : std::error_code(errno, std::generic_category());
        return operation_error(BackendErrorCode::StartFailed, "page-size lookup", cause);
    }
    const auto layout = make_ebpf_cache_storage_layout(cache_config_, static_cast<size_t>(page_size));
    auto secret = make_ebpf_cache_secret();
    if (!secret)
        return operation_error(BackendErrorCode::StartFailed, "cache secret generation", secret.error());
    const auto timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(cache_config_.pending_query_timeout());
    auto binding = native_session_->prepare_skeleton(
        {
            .cache_layout = layout,
            .secret = *secret,
            .pending_capacity = cache_config_.max_pending_queries(),
            .pending_timeout_ns = static_cast<uint64_t>(timeout.count()),
        }
    );
    if (!binding)
        return operation_error(BackendErrorCode::StartFailed, "skeleton preparation", binding.error());
    auto store = EbpfCacheStore::create(layout, binding->take_cache(), *secret);
    auto cleaner = PendingQueryCleaner::create(binding->take_pending(), timeout);
    dns_policy_ =
        std::make_unique<cache::DnsPolicy>(cache_config_.max_response_bytes(), cache_config_.cache_negative());
    cache_store_ = std::move(store);
    pending_cleaner_ = std::move(cleaner);
    event_consumer_ = std::make_unique<CorrelatedDnsEventConsumer>(*dns_policy_, *cache_store_, cache::boot_time);
    if (auto result = native_session_->create_log_ring(); !result)
        return operation_error(BackendErrorCode::StartFailed, "log ring creation", result.error());

    std::error_code last_xdp_error;
    bool xdp_attached = false;
    for (int attempt = 0; attempt < kAttachAttempts; ++attempt) {
        auto result = native_session_->attach_xdp(*ifindex);
        if (result) {
            xdp_attached = true;
            break;
        }
        last_xdp_error = result.error();
        if (auto waited = native_session_->wait_for(retry_delay(attempt)); !waited)
            return operation_error(BackendErrorCode::StartFailed, "XDP retry wait", waited.error());
    }
    if (!xdp_attached) {
        return operation_error(BackendErrorCode::StartFailed, "XDP attachment after retries", last_xdp_error);
    }

    std::error_code last_tc_error;
    bool tc_attached = false;
    for (int attempt = 0; attempt < kAttachAttempts; ++attempt) {
        auto tcx = native_session_->attach_tcx(*ifindex);
        if (tcx) {
            tc_attached = true;
            break;
        }

        last_tc_error = tcx.error();
        if (is_tcx_unsupported(tcx.error())) {
            auto legacy = native_session_->attach_legacy_tc(*ifindex);
            if (legacy) {
                tc_attached = true;
                break;
            }
            last_tc_error = legacy.error();
        }

        if (auto waited = native_session_->wait_for(retry_delay(attempt)); !waited)
            return operation_error(BackendErrorCode::StartFailed, "TC retry wait", waited.error());
    }
    if (!tc_attached) {
        return operation_error(BackendErrorCode::StartFailed, "TC attachment after retries", last_tc_error);
    }

    if (auto result = native_session_->create_packet_ring(*event_consumer_); !result)
        return operation_error(BackendErrorCode::StartFailed, "packet ring creation", result.error());

    cleanup_worker_ = std::make_unique<CleanupWorker>();
    if (auto result = cleanup_worker_->start(*cache_store_, *pending_cleaner_, config_.cleanup_interval(), timeout / 2);
        !result)
        return operation_error(BackendErrorCode::StartFailed, "cleanup thread startup", result.error());

    return {};
}

std::expected<void, BackendError> EbpfBackend::poll() {
    auto log_result = native_session_->poll_log_ring(0);
    if (!log_result && is_interrupted(log_result.error()))
        return {};

    auto packet_result = native_session_->poll_packet_ring(static_cast<int>(config_.packet_poll_timeout().count()));
    if (!packet_result) {
        if (is_interrupted(packet_result.error()))
            return {};
        return operation_error(BackendErrorCode::PollFailed, "packet ring poll", packet_result.error());
    }
    return {};
}

std::expected<void, BackendError> EbpfBackend::stop() {
    cleanup_worker_.reset();
    native_session_->close_packet_ring();
    event_consumer_.reset();
    dns_policy_.reset();
    cache_store_.reset();
    pending_cleaner_.reset();

    auto result = native_session_->release();
    if (!result)
        return operation_error(BackendErrorCode::StopFailed, "native resource release", result.error());
    return {};
}

} // namespace shinku::backend::ebpf
