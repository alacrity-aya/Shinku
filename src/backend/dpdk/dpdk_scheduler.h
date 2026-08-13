// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_packet_path.h"

#include <array>
#include <expected>

namespace shinku::backend::dpdk {

class DpdkCooperativeScheduler {
public:
    explicit DpdkCooperativeScheduler(std::array<DpdkPollTask*, 4> tasks) noexcept;

    [[nodiscard]] std::expected<void, BackendError> run_quantum();

private:
    std::array<DpdkPollTask*, 4> tasks_;
};

} // namespace shinku::backend::dpdk
