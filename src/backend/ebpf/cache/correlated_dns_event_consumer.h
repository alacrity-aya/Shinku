// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/packet_event_consumer.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"
#include "cache/dns_policy.h"

namespace shinku::backend::ebpf {

using EbpfCacheTimeSource = cache::CacheTime (*)() noexcept;

class CorrelatedDnsEventConsumer final: public PacketEventConsumer {
public:
    CorrelatedDnsEventConsumer(
        cache::DnsPolicy& policy,
        cache::CacheStore& store,
        EbpfCacheTimeSource time_source
    ) noexcept;

    void consume(std::span<const std::byte> sample) noexcept override;

private:
    cache::DnsPolicy& policy_;
    cache::CacheStore& store_;
    EbpfCacheTimeSource time_source_;
};

} // namespace shinku::backend::ebpf
