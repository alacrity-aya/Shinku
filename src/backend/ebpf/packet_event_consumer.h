// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <cstddef>
#include <span>

namespace shinku::backend::ebpf {

class PacketEventConsumer {
public:
    PacketEventConsumer() = default;
    virtual ~PacketEventConsumer() = default;

    PacketEventConsumer(const PacketEventConsumer&) = delete;
    PacketEventConsumer& operator=(const PacketEventConsumer&) = delete;
    PacketEventConsumer(PacketEventConsumer&&) = delete;
    PacketEventConsumer& operator=(PacketEventConsumer&&) = delete;

    virtual void consume(std::span<const std::byte> sample) noexcept = 0;
};

} // namespace shinku::backend::ebpf
