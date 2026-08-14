// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_packet_pool.h"

#include "backend/dpdk/dpdk_eal.h"
#include "backend/dpdk/dpdk_error.h"

#include <array>
#include <cassert>
#include <expected>
#include <optional>
#include <rte_errno.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <system_error>

namespace shinku::backend::dpdk {
namespace {

constexpr unsigned kMempoolCacheSize = 256;
constexpr unsigned kBurstAllowance = 2 * 32;

std::optional<std::error_code> dpdk_errno() noexcept {
    if (rte_errno == 0)
        return std::nullopt;
    return std::error_code(rte_errno, std::generic_category());
}

unsigned packet_pool_capacity(const std::array<DpdkDescriptorCounts, 2>& descriptors) noexcept {
    unsigned required = kBurstAllowance + kMempoolCacheSize;
    for (const DpdkDescriptorCounts counts: descriptors) {
        required += counts.rx;
        required += counts.tx;
    }

    unsigned power_of_two = 1;
    while (power_of_two - 1 < required)
        power_of_two *= 2;
    return power_of_two - 1;
}

} // namespace

ProductionDpdkPacketPool::ProductionDpdkPacketPool(ProductionDpdkEal& eal) noexcept: eal_(eal) {}

ProductionDpdkPacketPool::~ProductionDpdkPacketPool() {
    auto _ = close();
}

std::expected<void, DpdkError> ProductionDpdkPacketPool::create(
    const std::array<DpdkDescriptorCounts, 2>& descriptors,
    int socket_id
) {
    assert(pool_ == nullptr);
    rte_errno = 0;
    pool_ = rte_pktmbuf_pool_create(
        "shinku-packets",
        packet_pool_capacity(descriptors),
        kMempoolCacheSize,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        socket_id
    );
    if (pool_ == nullptr) {
        return std::unexpected(DpdkError {
            .operation = "packet-pool creation",
            .detail = "shinku-packets",
            .cause = dpdk_errno(),
        });
    }
    eal_.acquire_packet_pool();
    return {};
}

bool ProductionDpdkPacketPool::owns_resources() const noexcept {
    return pool_ != nullptr;
}

std::expected<void, DpdkError> ProductionDpdkPacketPool::close() {
    if (pool_ == nullptr)
        return {};
    if (eal_.has_ports()) {
        return std::unexpected(DpdkError {
            .operation = "packet-pool cleanup",
            .detail = "DPDK ports still own queues backed by shinku-packets",
            .cause = std::make_error_code(std::errc::device_or_resource_busy),
        });
    }
    rte_mempool_free(pool_);
    pool_ = nullptr;
    eal_.release_packet_pool();
    return {};
}

rte_mempool& ProductionDpdkPacketPool::native_pool() const noexcept {
    assert(pool_ != nullptr);
    return *pool_;
}

} // namespace shinku::backend::dpdk
