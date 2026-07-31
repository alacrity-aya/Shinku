// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/ebpf_backend.h"

#include "backend/backend.h"
#include "backend/backend_error.h"
#include "backend/ebpf/ebpf_native_session.h"
#include "config/config.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace shinku::backend::ebpf {
namespace {

constexpr int kAttachAttempts = 5;
constexpr auto kAttachBaseDelay = std::chrono::milliseconds(50);
constexpr auto kAttachMaxDelay = std::chrono::milliseconds(800);
constexpr int kLogPollTimeoutMs = 100;

BackendError
make_error(BackendErrorCode code, std::string message, std::optional<std::error_code> cause = std::nullopt) {
    return BackendError {
        .code = code,
        .message = std::move(message),
        .cause = cause,
    };
}

BackendError operation_error(BackendErrorCode code, std::string_view operation, std::error_code cause) {
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

void report_log_poll_error(const std::error_code& error) noexcept {
    std::println(stderr, "warning: eBPF log ring poll failed: {} (continuing)", error.message());
}

} // namespace

struct EbpfBackend::CleanupWorker {
    [[nodiscard]] std::expected<void, std::error_code>
    start(EbpfNativeSession& session, std::chrono::milliseconds interval) {
        try {
            thread = std::jthread([&session, interval](std::stop_token token) noexcept {
                run(std::move(token), session, interval);
            });
        } catch (const std::system_error& error) {
            return std::unexpected(error.code());
        }
        return {};
    }

    static void run(std::stop_token token, EbpfNativeSession& session, std::chrono::milliseconds interval) noexcept {
        std::mutex wait_mutex;
        std::condition_variable_any wake;

        while (!token.stop_requested()) {
            {
                std::unique_lock lock(wait_mutex);
                const bool stopped = wake.wait_for(lock, token, interval, [&token] { return token.stop_requested(); });
                if (stopped || token.stop_requested())
                    break;
            }

            [[maybe_unused]] auto result = session.cleanup_expired_entries();
        }
    }

    std::jthread thread;
};

EbpfBackend::EbpfBackend(
    config::EbpfConfig ebpf_config,
    [[maybe_unused]] config::CacheConfig cache_config,
    std::unique_ptr<EbpfNativeSession> native_session
):
    config_(std::move(ebpf_config)),
    native_session_(std::move(native_session)) {
    assert(native_session_ != nullptr && "EbpfBackend requires a valid native_session");
}

EbpfBackend::~EbpfBackend() = default;

std::expected<void, BackendError> EbpfBackend::probe() {
    auto privileges = native_session_->has_required_privileges();
    if (!privileges)
        return std::unexpected(operation_error(BackendErrorCode::ProbeFailed, "privilege probe", privileges.error()));
    if (!*privileges) {
        return std::unexpected(make_error(
            BackendErrorCode::PermissionDenied,
            "eBPF backend requires root or effective CAP_BPF, CAP_NET_ADMIN, and CAP_SYS_ADMIN"
        ));
    }

    auto interface = native_session_->interface_exists(config_.iface());
    if (!interface)
        return std::unexpected(operation_error(BackendErrorCode::ProbeFailed, "interface probe", interface.error()));
    if (!*interface) {
        return std::unexpected(
            make_error(BackendErrorCode::WrongConfig, std::format("eBPF interface does not exist: {}", config_.iface()))
        );
    }

    auto arena = native_session_->arena_supported();
    if (!arena) {
        if (arena.error() == std::errc::operation_not_supported)
            return std::unexpected(
                make_error(BackendErrorCode::Unsupported, "host kernel does not support BPF arena maps")
            );
        return std::unexpected(operation_error(BackendErrorCode::ProbeFailed, "BPF arena probe", arena.error()));
    }
    if (!*arena)
        return std::unexpected(
            make_error(BackendErrorCode::Unsupported, "host kernel does not support BPF arena maps")
        );
    return {};
}

std::expected<void, BackendError> EbpfBackend::start() {
    auto ifindex = native_session_->interface_index(config_.iface());
    if (!ifindex)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "interface lookup", ifindex.error()));

    if (auto result = native_session_->prepare_skeleton(config_.arena_pages()); !result)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "skeleton preparation", result.error()));
    if (auto result = native_session_->create_cache_bridge(); !result)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "cache bridge creation", result.error()));
    if (auto result = native_session_->create_log_ring(); !result)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "log ring creation", result.error()));

    std::optional<std::error_code> last_xdp_error;
    bool xdp_attached = false;
    for (int attempt = 0; attempt < kAttachAttempts; ++attempt) {
        auto result = native_session_->attach_xdp(*ifindex);
        if (result) {
            xdp_attached = true;
            break;
        }
        last_xdp_error = result.error();
        if (auto waited = native_session_->wait_for(retry_delay(attempt)); !waited)
            return std::unexpected(operation_error(BackendErrorCode::StartFailed, "XDP retry wait", waited.error()));
    }
    if (!xdp_attached) {
        return std::unexpected(operation_error(
            BackendErrorCode::StartFailed,
            "XDP attachment after retries",
            last_xdp_error.value_or(std::make_error_code(std::errc::io_error))
        ));
    }

    std::optional<std::error_code> last_tc_error;
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
            return std::unexpected(operation_error(BackendErrorCode::StartFailed, "TC retry wait", waited.error()));
    }
    if (!tc_attached) {
        return std::unexpected(operation_error(
            BackendErrorCode::StartFailed,
            "TC attachment after retries",
            last_tc_error.value_or(std::make_error_code(std::errc::io_error))
        ));
    }

    if (auto result = native_session_->create_packet_ring(); !result)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "packet ring creation", result.error()));

    cleanup_worker_ = std::make_unique<CleanupWorker>();
    if (auto result = cleanup_worker_->start(*native_session_, config_.cleanup_interval()); !result)
        return std::unexpected(operation_error(BackendErrorCode::StartFailed, "cleanup thread startup", result.error())
        );

    return {};
}

std::expected<PollStatus, BackendError> EbpfBackend::poll() {
    int log_work = 0;
    auto log_result = native_session_->poll_log_ring(kLogPollTimeoutMs);
    if (!log_result) {
        if (is_interrupted(log_result.error()))
            return PollStatus::NoWork;
        report_log_poll_error(log_result.error());
    } else {
        log_work = *log_result;
    }

    auto packet_result = native_session_->poll_packet_ring(static_cast<int>(config_.packet_poll_timeout().count()));
    if (!packet_result) {
        if (is_interrupted(packet_result.error()))
            return PollStatus::NoWork;
        return std::unexpected(
            operation_error(BackendErrorCode::PollFailed, "packet ring poll", packet_result.error())
        );
    }
    return log_work > 0 || *packet_result > 0 ? PollStatus::WorkDone : PollStatus::NoWork;
}

std::expected<void, BackendError> EbpfBackend::stop() {
    if (cleanup_worker_)
        cleanup_worker_.reset();

    auto result = native_session_->release();
    if (!result)
        return std::unexpected(
            operation_error(BackendErrorCode::StopFailed, "native resource release", result.error())
        );
    return {};
}

} // namespace shinku::backend::ebpf
