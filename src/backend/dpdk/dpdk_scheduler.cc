// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_scheduler.h"

#include "backend/backend_error.h"
#include "backend/dpdk/dpdk_packet_path.h"

#include <expected>

namespace shinku::backend::dpdk {

/// Store references to the four poll tasks that make up a scheduling quantum.
DpdkCooperativeScheduler::DpdkCooperativeScheduler(
    DpdkPollTask& client,
    DpdkPollTask& service,
    DpdkPollTask& cache,
    DpdkPollTask& pending
) noexcept:
    client_(client),
    service_(service),
    cache_(cache),
    pending_(pending) {}

/// Run each poll task once in fixed order (client, service, cache, pending), aborting the
/// quantum and propagating the first failure.
std::expected<void, BackendError> DpdkCooperativeScheduler::run_quantum() {
    if (auto result = client_.run(); !result)
        return result;
    if (auto result = service_.run(); !result)
        return result;
    if (auto result = cache_.run(); !result)
        return result;
    if (auto result = pending_.run(); !result)
        return result;
    return {};
}

} // namespace shinku::backend::dpdk
