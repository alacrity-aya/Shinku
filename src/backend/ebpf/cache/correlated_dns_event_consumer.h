// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "backend/ebpf/packet_event_consumer.h"
#include "cache/cache_store.h"
#include "cache/cache_time.h"
#include "cache/dns_policy.h"

namespace shinku::backend::ebpf {

/// Function pointer returning the current @ref cache::CacheTime, injectable for tests.
using EbpfCacheTimeSource = cache::CacheTime (*)() noexcept;

/**
 * @brief Consumes correlated DNS packet events from the BPF ring and caches them.
 *
 * For each sample the consumer runs the DNS policy to classify the response,
 * then synchronously stores the resulting candidate in the cache. The time
 * source is injected so tests can control cache timestamps.
 */
class CorrelatedDnsEventConsumer final: public PacketEventConsumer {
public:
    /// @brief Construct the consumer over its policy, store, and time source.
    CorrelatedDnsEventConsumer(
        cache::DnsPolicy& policy,
        cache::CacheStore& store,
        EbpfCacheTimeSource time_source
    ) noexcept;

    /// @brief Consume one correlated-DNS ring sample and update the cache.
    void consume(std::span<const std::byte> sample) noexcept override;

private:
    cache::DnsPolicy& policy_; ///< The DNS cache policy.
    cache::CacheStore& store_; ///< The cache store to publish into.
    EbpfCacheTimeSource time_source_; ///< Injected clock used to stamp cache times.
};

} // namespace shinku::backend::ebpf
