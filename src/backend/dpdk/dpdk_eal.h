// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/dpdk/dpdk_error.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace shinku::backend::dpdk {

class ProductionDpdkPacketPool;
class ProductionDpdkPort;

class DpdkEal {
public:
    virtual ~DpdkEal() = default;

    DpdkEal(const DpdkEal&) = delete;
    DpdkEal& operator=(const DpdkEal&) = delete;
    DpdkEal(DpdkEal&&) = delete;
    DpdkEal& operator=(DpdkEal&&) = delete;

    [[nodiscard]] virtual std::expected<void, DpdkError> initialize(std::span<const std::string> arguments) = 0;
    [[nodiscard]] virtual int main_socket_id() const noexcept = 0;
    [[nodiscard]] virtual std::expected<void, DpdkError> close() = 0;

protected:
    DpdkEal() = default;
};

class ProductionDpdkEal final: public DpdkEal {
public:
    ProductionDpdkEal() = default;
    ~ProductionDpdkEal() override;

    [[nodiscard]] std::expected<void, DpdkError> initialize(std::span<const std::string> arguments) override;
    [[nodiscard]] int main_socket_id() const noexcept override;
    [[nodiscard]] std::expected<void, DpdkError> close() override;

private:
    friend class ProductionDpdkPacketPool;
    friend class ProductionDpdkPort;

    void acquire_port() noexcept;
    void release_port() noexcept;
    void acquire_packet_pool() noexcept;
    void release_packet_pool() noexcept;
    [[nodiscard]] bool has_ports() const noexcept;

    bool initialized_ = false;
    bool cleanup_attempted_ = false;
    uint16_t owned_ports_ = 0;
    bool owns_packet_pool_ = false;
    int main_socket_id_ = -1;
    std::optional<DpdkError> terminal_cleanup_error_;
};

} // namespace shinku::backend::dpdk
