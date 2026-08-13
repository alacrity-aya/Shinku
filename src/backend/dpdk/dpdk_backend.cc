// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_backend.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_native_session.h"
#include "backend/dpdk/dpdk_packet_path.h"
#include "backend/dpdk/dpdk_scheduler.h"

#include <array>
#include <cassert>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace shinku::backend::dpdk {
namespace {

std::unexpected<BackendError> native_error(BackendErrorCode code, const DpdkNativeError& error) {
    std::string message = std::format("DPDK {} failed", error.operation);
    if (!error.detail.empty())
        message += ": " + error.detail;
    if (error.cause.has_value())
        message += ": " + error.cause->message();
    return std::unexpected(BackendError { .code = code, .message = std::move(message), .cause = error.cause });
}

} // namespace

DpdkBackend::DpdkBackend(std::span<const std::string> eal_arguments, std::unique_ptr<DpdkNativeSession> native_session):
    eal_arguments_(eal_arguments.begin(), eal_arguments.end()),
    native_session_(std::move(native_session)) {
    assert(native_session_ != nullptr);
}

DpdkBackend::~DpdkBackend() = default;

std::expected<void, BackendError> DpdkBackend::probe() {
    return {};
}

std::expected<void, BackendError> DpdkBackend::start() {
    spdlog::info("starting DPDK backend");
    if (auto result = native_session_->start(eal_arguments_); !result)
        return native_error(BackendErrorCode::StartFailed, result.error());

    client_path_ = std::make_unique<DpdkPacketPath>(*native_session_, PortSide::Client, PortSide::Service);
    service_path_ = std::make_unique<DpdkPacketPath>(*native_session_, PortSide::Service, PortSide::Client);
    scheduler_ = std::make_unique<DpdkCooperativeScheduler>(
        std::array<DpdkPollTask*, 4> { client_path_.get(), service_path_.get(), nullptr, nullptr }
    );
    spdlog::info("DPDK backend started");
    return {};
}

std::expected<void, BackendError> DpdkBackend::poll() {
    assert(scheduler_ != nullptr);
    return scheduler_->run_quantum();
}

std::expected<void, BackendError> DpdkBackend::stop() {
    scheduler_.reset();
    service_path_.reset();
    client_path_.reset();

    auto result = native_session_->release();
    if (!result)
        return native_error(BackendErrorCode::StopFailed, result.error());
    spdlog::info("DPDK backend stopped");
    return {};
}

} // namespace shinku::backend::dpdk
