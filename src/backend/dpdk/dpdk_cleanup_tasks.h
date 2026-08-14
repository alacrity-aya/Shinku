// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_packet_path.h"

#include <optional>

namespace shinku::backend::dpdk {

class DpdkCacheCleanupTask final: public DpdkPollTask {
public:
    explicit DpdkCacheCleanupTask(DpdkCacheContext& context) noexcept: context_(context) {}
    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    DpdkCacheContext& context_;
    std::optional<cache::CacheTime> deadline_;
    bool warning_emitted_ { false };
};

class DpdkPendingCleanupTask final: public DpdkPollTask {
public:
    explicit DpdkPendingCleanupTask(DpdkCacheContext& context) noexcept: context_(context) {}
    [[nodiscard]] std::expected<void, BackendError> run() override;

private:
    DpdkCacheContext& context_;
    std::optional<cache::CacheTime> deadline_;
    bool warning_emitted_ { false };
};

} // namespace shinku::backend::dpdk
