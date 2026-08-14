// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_packet_path.h"

#include <expected>

namespace shinku::backend::dpdk {

class DpdkCooperativeScheduler {
public:
    DpdkCooperativeScheduler(
        DpdkPollTask& client,
        DpdkPollTask& service,
        DpdkPollTask& cache,
        DpdkPollTask& pending
    ) noexcept;

    [[nodiscard]] std::expected<void, BackendError> run_quantum();

private:
    DpdkPollTask& client_;
    DpdkPollTask& service_;
    DpdkPollTask& cache_;
    DpdkPollTask& pending_;
};

} // namespace shinku::backend::dpdk
