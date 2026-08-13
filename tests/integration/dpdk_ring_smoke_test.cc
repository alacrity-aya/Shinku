// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/backend_runner.h"
#include "backend/dpdk/dpdk_backend.h"
#include "backend/dpdk/dpdk_native_session.h"
#include "config/config.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <print>
#include <ranges>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using shinku::backend::StopCondition;
using shinku::backend::StopReason;
using shinku::backend::StopRequest;

constexpr std::array<std::byte, 42> kClientFrame {
    std::byte { 0x00 }, std::byte { 0x11 }, std::byte { 0x22 }, std::byte { 0x33 }, std::byte { 0x44 },
    std::byte { 0x55 }, std::byte { 0x66 }, std::byte { 0x77 }, std::byte { 0x88 }, std::byte { 0x99 },
    std::byte { 0xaa }, std::byte { 0xbb }, std::byte { 0x08 }, std::byte { 0x06 }, std::byte { 0x00 },
    std::byte { 0x01 }, std::byte { 0x08 }, std::byte { 0x00 }, std::byte { 0x06 }, std::byte { 0x04 },
    std::byte { 0x00 }, std::byte { 0x01 }, std::byte { 0x66 }, std::byte { 0x77 }, std::byte { 0x88 },
    std::byte { 0x99 }, std::byte { 0xaa }, std::byte { 0xbb }, std::byte { 0xc0 }, std::byte { 0x00 },
    std::byte { 0x02 }, std::byte { 0x01 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0xc0 }, std::byte { 0x00 },
    std::byte { 0x02 }, std::byte { 0x02 },
};

constexpr std::array<std::byte, 64> kServiceFrame {
    std::byte { 0x66 }, std::byte { 0x77 }, std::byte { 0x88 }, std::byte { 0x99 }, std::byte { 0xaa },
    std::byte { 0xbb }, std::byte { 0x00 }, std::byte { 0x11 }, std::byte { 0x22 }, std::byte { 0x33 },
    std::byte { 0x44 }, std::byte { 0x55 }, std::byte { 0x86 }, std::byte { 0xdd }, std::byte { 0x60 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x0a },
    std::byte { 0x06 }, std::byte { 0x40 }, std::byte { 0x20 }, std::byte { 0x01 }, std::byte { 0x0d },
    std::byte { 0xb8 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x01 }, std::byte { 0x20 },
    std::byte { 0x01 }, std::byte { 0x0d }, std::byte { 0xb8 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x02 }, std::byte { 0x00 }, std::byte { 0x35 }, std::byte { 0xc0 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x50 }, std::byte { 0x02 }, std::byte { 0x20 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
};

using Frame = std::vector<std::byte>;

void write_u16(Frame& frame, size_t offset, uint16_t value) {
    frame[offset] = static_cast<std::byte>(value >> 8);
    frame[offset + 1] = static_cast<std::byte>(value & 0xff);
}

Frame make_ipv4_udp_frame(
    uint16_t source_port,
    uint16_t destination_port,
    std::span<const std::byte> payload,
    bool vlan
) {
    const size_t ip_offset = vlan ? 18 : 14;
    Frame frame(ip_offset + 20 + 8 + payload.size());
    const std::array<std::byte, 12> ethernet_addresses {
        std::byte { 0x00 }, std::byte { 0x11 }, std::byte { 0x22 }, std::byte { 0x33 },
        std::byte { 0x44 }, std::byte { 0x55 }, std::byte { 0x66 }, std::byte { 0x77 },
        std::byte { 0x88 }, std::byte { 0x99 }, std::byte { 0xaa }, std::byte { 0xbb },
    };
    std::ranges::copy(ethernet_addresses, frame.begin());
    if (vlan) {
        write_u16(frame, 12, 0x8100);
        write_u16(frame, 14, 100);
        write_u16(frame, 16, 0x0800);
    } else {
        write_u16(frame, 12, 0x0800);
    }

    frame[ip_offset] = std::byte { 0x45 };
    write_u16(frame, ip_offset + 2, static_cast<uint16_t>(20 + 8 + payload.size()));
    frame[ip_offset + 8] = std::byte { 64 };
    frame[ip_offset + 9] = std::byte { 17 };
    frame[ip_offset + 12] = std::byte { 192 };
    frame[ip_offset + 13] = std::byte { 0 };
    frame[ip_offset + 14] = std::byte { 2 };
    frame[ip_offset + 15] = std::byte { 1 };
    frame[ip_offset + 16] = std::byte { 198 };
    frame[ip_offset + 17] = std::byte { 51 };
    frame[ip_offset + 18] = std::byte { 100 };
    frame[ip_offset + 19] = std::byte { 2 };
    uint32_t checksum = 0;
    for (size_t offset = 0; offset < 20; offset += 2) {
        checksum += static_cast<uint32_t>(std::to_integer<uint8_t>(frame[ip_offset + offset])) << 8;
        checksum += std::to_integer<uint8_t>(frame[ip_offset + offset + 1]);
    }
    while ((checksum >> 16) != 0)
        checksum = (checksum & 0xffff) + (checksum >> 16);
    write_u16(frame, ip_offset + 10, static_cast<uint16_t>(~checksum));

    const size_t udp_offset = ip_offset + 20;
    write_u16(frame, udp_offset, source_port);
    write_u16(frame, udp_offset + 2, destination_port);
    write_u16(frame, udp_offset + 4, static_cast<uint16_t>(8 + payload.size()));
    std::ranges::copy(payload, frame.begin() + static_cast<std::ptrdiff_t>(udp_offset + 8));
    return frame;
}

const std::array<std::byte, 4> kNonDnsPayload { std::byte { 0xde },
                                                std::byte { 0xad },
                                                std::byte { 0xbe },
                                                std::byte { 0xef } };
const std::array<std::byte, 3> kMalformedDnsPayload { std::byte { 0x12 }, std::byte { 0x34 }, std::byte { 0x01 } };
const std::array<std::byte, 25> kUnsupportedDnsPayload {
    std::byte { 0x12 }, std::byte { 0x34 }, std::byte { 0x01 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x01 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x00 },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x07 }, std::byte { 'e' },  std::byte { 'x' },
    std::byte { 'a' },  std::byte { 'm' },  std::byte { 'p' },  std::byte { 'l' },  std::byte { 'e' },
    std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x1c }, std::byte { 0x00 }, std::byte { 0x01 },
};
const Frame kVlanFrame = make_ipv4_udp_frame(1234, 4321, kNonDnsPayload, true);
const Frame kNonDnsUdpFrame = make_ipv4_udp_frame(1234, 4321, kNonDnsPayload, false);
const Frame kMalformedDnsFrame = make_ipv4_udp_frame(53000, 53, kMalformedDnsPayload, false);
const Frame kUnsupportedDnsFrame = make_ipv4_udp_frame(53000, 53, kUnsupportedDnsPayload, false);

std::array<std::span<const std::byte>, 6> representative_frames() {
    return {
        std::span(kClientFrame),    std::span(kServiceFrame),      std::span(kVlanFrame),
        std::span(kNonDnsUdpFrame), std::span(kMalformedDnsFrame), std::span(kUnsupportedDnsFrame),
    };
}

class RingSmokeStopCondition final: public StopCondition {
public:
    std::optional<StopRequest> poll() noexcept override {
        if (stage_++ == 0)
            return std::nullopt;
        if (stage_ == 2) {
            inject_frames();
            return std::nullopt;
        }
        verify_frames();
        return StopRequest { .reason = StopReason::Manual };
    }

    [[nodiscard]] bool passed() const noexcept {
        return passed_;
    }

    [[nodiscard]] std::string_view failure() const noexcept {
        return failure_;
    }

private:
    bool enqueue_frame(rte_ring* ring, std::span<const std::byte> bytes) noexcept {
        rte_mbuf* packet = rte_pktmbuf_alloc(pool_);
        if (packet == nullptr) {
            fail("failed to allocate smoke mbuf");
            return false;
        }
        void* data = rte_pktmbuf_append(packet, bytes.size());
        if (data == nullptr) {
            rte_pktmbuf_free(packet);
            fail("failed to append smoke frame");
            return false;
        }
        std::memcpy(data, bytes.data(), bytes.size());
        if (rte_ring_enqueue(ring, packet) != 0) {
            rte_pktmbuf_free(packet);
            fail("failed to enqueue smoke frame");
            return false;
        }
        return true;
    }

    bool dequeue_and_compare(rte_ring* ring, std::span<const std::byte> expected) noexcept {
        void* object = nullptr;
        if (rte_ring_dequeue(ring, &object) != 0) {
            fail("forwarded frame was not available on the expected egress ring");
            return false;
        }
        auto* packet = static_cast<rte_mbuf*>(object);
        const bool shape_matches = packet->nb_segs == 1 && packet->next == nullptr && packet->pkt_len == expected.size()
            && packet->data_len == expected.size();
        const bool bytes_match =
            shape_matches && std::memcmp(rte_pktmbuf_mtod(packet, const void*), expected.data(), expected.size()) == 0;
        rte_pktmbuf_free(packet);
        if (!bytes_match) {
            fail("forwarded frame bytes changed");
            return false;
        }
        return true;
    }

    void inject_frames() noexcept {
        client_ring_ = rte_ring_lookup("ETH_RXTX0_net_ring0");
        service_ring_ = rte_ring_lookup("ETH_RXTX0_net_ring1");
        if (client_ring_ == nullptr || service_ring_ == nullptr) {
            fail("EAL net_ring vdev endpoints were not created");
            return;
        }
        if (client_ring_ == service_ring_) {
            fail("EAL net_ring vdev endpoints were not distinct");
            return;
        }

        pool_ = rte_mempool_lookup("shinku-packets");
        if (pool_ == nullptr) {
            fail("Session packet pool was not available to the smoke fixture");
            return;
        }
        for (const std::span<const std::byte> frame: representative_frames()) {
            if (!enqueue_frame(service_ring_, frame))
                return;
        }
    }

    void verify_frames() noexcept {
        if (!passed_ || pool_ == nullptr)
            return;
        for (const std::span<const std::byte> frame: representative_frames()) {
            if (!dequeue_and_compare(client_ring_, frame))
                return;
        }
    }

    void fail(std::string message) noexcept {
        if (!passed_)
            return;
        passed_ = false;
        failure_ = std::move(message);
    }

    int stage_ = 0;
    bool passed_ = true;
    std::string failure_;
    rte_ring* client_ring_ = nullptr;
    rte_ring* service_ring_ = nullptr;
    rte_mempool* pool_ = nullptr;
};

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> eal_arguments;
    eal_arguments.reserve(static_cast<size_t>(argc - 1));
    for (int index = 1; index < argc; ++index)
        eal_arguments.emplace_back(argv[index]);

    auto backend = std::make_unique<shinku::backend::dpdk::DpdkBackend>(
        eal_arguments,
        std::make_unique<shinku::backend::dpdk::ProductionDpdkNativeSession>()
    );
    shinku::backend::BackendRunner runner(std::move(backend));
    RingSmokeStopCondition stop_condition;

    auto result = runner.run(stop_condition);
    if (!result) {
        std::println(stderr, "DPDK ring smoke lifecycle failed: {}", result.error().message);
        return 1;
    }
    if (!stop_condition.passed()) {
        std::println(stderr, "DPDK ring smoke failed: {}", stop_condition.failure());
        return 1;
    }
    std::println("DPDK ring smoke passed: EAL net_ring vdevs started and service-to-client frames were preserved");
    return 0;
}
