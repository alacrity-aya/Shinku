// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <span>

namespace shinku::backend::ebpf {

/**
 * @brief Abstract sink for raw packet-ring samples from the BPF program.
 *
 * The backend implements this to receive each correlated packet event emitted
 * by the XDP/TC program via the BPF ring buffer.
 */
class PacketEventConsumer {
public:
    PacketEventConsumer() = default;
    virtual ~PacketEventConsumer() = default;

    PacketEventConsumer(const PacketEventConsumer&) = delete;
    PacketEventConsumer& operator=(const PacketEventConsumer&) = delete;
    PacketEventConsumer(PacketEventConsumer&&) = delete;
    PacketEventConsumer& operator=(PacketEventConsumer&&) = delete;

    /// @brief Consume one raw sample from the packet ring buffer.
    /// @param sample The raw bytes of the ring-buffer sample.
    virtual void consume(std::span<const std::byte> sample) noexcept = 0;
};

} // namespace shinku::backend::ebpf
