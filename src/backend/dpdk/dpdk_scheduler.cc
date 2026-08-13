// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_scheduler.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_packet_path.h"

#include <array>
#include <expected>

namespace shinku::backend::dpdk {

DpdkCooperativeScheduler::DpdkCooperativeScheduler(std::array<DpdkPollTask*, 4> tasks) noexcept: tasks_(tasks) {}

std::expected<void, BackendError> DpdkCooperativeScheduler::run_quantum() {
    for (auto* task: tasks_) {
        if (task == nullptr)
            continue;
        if (auto result = task->run(); !result)
            return result;
    }
    return {};
}

} // namespace shinku::backend::dpdk
