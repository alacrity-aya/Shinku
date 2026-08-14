// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_error.h"

#include <array>
#include <cstdint>
#include <expected>

struct rte_mempool;

namespace shinku::backend::dpdk {

class ProductionDpdkEal;
class ProductionDpdkPort;

struct DpdkDescriptorCounts {
    uint16_t rx;
    uint16_t tx;
};

class DpdkPacketPool {
public:
    virtual ~DpdkPacketPool() = default;

    DpdkPacketPool(const DpdkPacketPool&) = delete;
    DpdkPacketPool& operator=(const DpdkPacketPool&) = delete;
    DpdkPacketPool(DpdkPacketPool&&) = delete;
    DpdkPacketPool& operator=(DpdkPacketPool&&) = delete;

    [[nodiscard]] virtual std::expected<void, DpdkError>
    create(const std::array<DpdkDescriptorCounts, 2>& descriptors, int socket_id) = 0;
    [[nodiscard]] virtual bool owns_resources() const noexcept = 0;
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkPacketPool() = default;
};

class ProductionDpdkPacketPool final: public DpdkPacketPool {
public:
    explicit ProductionDpdkPacketPool(ProductionDpdkEal& eal) noexcept;
    ~ProductionDpdkPacketPool() override;

    [[nodiscard]] std::expected<void, DpdkError>
    create(const std::array<DpdkDescriptorCounts, 2>& descriptors, int socket_id) override;
    [[nodiscard]] bool owns_resources() const noexcept override;
    [[nodiscard]] std::expected<void, DpdkError> close() override;

private:
    friend class ProductionDpdkPort;

    [[nodiscard]] rte_mempool& native_pool() const noexcept;

    ProductionDpdkEal& eal_;
    rte_mempool* pool_ = nullptr;
};

} // namespace shinku::backend::dpdk
