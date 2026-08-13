// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_native_session.h"

#include <expected>

namespace shinku::backend::dpdk {

class DpdkPollTask {
public:
    virtual ~DpdkPollTask() = default;
    [[nodiscard]] virtual std::expected<void, BackendError> run() = 0;
};

class DpdkPacketPath final: public DpdkPollTask {
public:
    DpdkPacketPath(DpdkNativeSession& session, PortSide source, PortSide destination) noexcept;

    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    DpdkNativeSession* session_;
    PortSide source_;
    PortSide destination_;
    bool frame_warning_emitted_ = false;
};

} // namespace shinku::backend::dpdk
