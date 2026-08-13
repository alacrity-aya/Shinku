// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

struct rte_mbuf;

namespace shinku::backend::dpdk {

enum class PortSide : uint8_t {
    Client,
    Service,
};

struct DpdkNativeError {
    std::string operation;
    std::string detail;
    std::optional<std::error_code> cause;
};

class DpdkNativeSession {
public:
    virtual ~DpdkNativeSession() = default;

    DpdkNativeSession(const DpdkNativeSession&) = delete;
    DpdkNativeSession& operator=(const DpdkNativeSession&) = delete;
    DpdkNativeSession(DpdkNativeSession&&) = delete;
    DpdkNativeSession& operator=(DpdkNativeSession&&) = delete;

    [[nodiscard]] virtual std::expected<void, DpdkNativeError> start(std::span<const std::string> eal_arguments) = 0;
    [[nodiscard]] virtual uint16_t receive(PortSide side, rte_mbuf** packets, uint16_t capacity) noexcept = 0;
    [[nodiscard]] virtual uint16_t transmit(PortSide side, rte_mbuf** packets, uint16_t count) noexcept = 0;
    virtual void free_packet(rte_mbuf* packet) noexcept = 0;
    [[nodiscard]] virtual std::string_view port_identity(PortSide side) const noexcept = 0;
    [[nodiscard]] virtual std::expected<void, DpdkNativeError> release() = 0;

protected:
    DpdkNativeSession() = default;
};

class ProductionDpdkNativeSession final: public DpdkNativeSession {
public:
    struct Resources;

    ProductionDpdkNativeSession();
    ~ProductionDpdkNativeSession() override;

    [[nodiscard]] std::expected<void, DpdkNativeError> start(std::span<const std::string> eal_arguments) override;
    [[nodiscard]] uint16_t receive(PortSide side, rte_mbuf** packets, uint16_t capacity) noexcept override;
    [[nodiscard]] uint16_t transmit(PortSide side, rte_mbuf** packets, uint16_t count) noexcept override;
    void free_packet(rte_mbuf* packet) noexcept override;
    [[nodiscard]] std::string_view port_identity(PortSide side) const noexcept override;
    [[nodiscard]] std::expected<void, DpdkNativeError> release() override;

private:
    std::unique_ptr<Resources> resources_;
};

} // namespace shinku::backend::dpdk
