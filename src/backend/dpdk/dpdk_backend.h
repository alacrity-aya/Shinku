// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend.h"
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace shinku::backend::dpdk {

class DpdkCooperativeScheduler;
class DpdkNativeSession;
class DpdkPacketPath;

class DpdkBackend final: public Backend {
public:
    DpdkBackend(std::span<const std::string> eal_arguments, std::unique_ptr<DpdkNativeSession> native_session);
    ~DpdkBackend() override;

protected:
    [[nodiscard]] std::expected<void, BackendError> probe() override;
    [[nodiscard]] std::expected<void, BackendError> start() override;
    [[nodiscard]] std::expected<void, BackendError> poll() override;
    [[nodiscard]] std::expected<void, BackendError> stop() override;

private:
    std::vector<std::string> eal_arguments_;
    std::unique_ptr<DpdkNativeSession> native_session_;
    std::unique_ptr<DpdkPacketPath> client_path_;
    std::unique_ptr<DpdkPacketPath> service_path_;
    std::unique_ptr<DpdkCooperativeScheduler> scheduler_;
};

} // namespace shinku::backend::dpdk
