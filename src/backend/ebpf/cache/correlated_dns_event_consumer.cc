// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/correlated_dns_event_consumer.h"

#include "ebpf_cache_abi.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>

namespace shinku::backend::ebpf {

/// Store the policy, store, and injected time source for the consumer.
CorrelatedDnsEventConsumer::CorrelatedDnsEventConsumer(
    cache::DnsPolicy& policy,
    cache::CacheStore& store,
    EbpfCacheTimeSource time_source
) noexcept:
    policy_(policy),
    store_(store),
    time_source_(time_source) {}

/// Validate and decode one correlated-DNS ring sample, classify it via the
/// policy, and store the resulting candidate; malformed or unclassifiable
/// samples are silently dropped.
void CorrelatedDnsEventConsumer::consume(std::span<const std::byte> sample) noexcept {
    if (sample.size() != sizeof(ebpf_correlated_dns_event))
        return;

    // The header fields are a contiguous 16-byte block in the ABI layout
    // (offsets 0/8/12/14, pinned by static_asserts in ebpf_cache_abi.h), so a
    // single memcpy into a local header suffices; memcpy initializes every
    // field we read, and local access is alignment-safe regardless of where
    // the ring-buffer sample happens to start.
    ebpf_correlated_dns_event header;
    std::memcpy(&header, sample.data(), SHINKU_EBPF_CORRELATED_EVENT_HEADER_BYTES);

    const uint16_t active_size = ntohs(header.response_size);
    if (active_size < 12 || active_size > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES)
        return;

    const auto response = sample.subspan(SHINKU_EBPF_CORRELATED_EVENT_HEADER_BYTES, active_size);
    auto candidate = policy_.classify_response(
        response,
        cache::CacheNamespace {
            .destination_ipv4 = ntohl(header.destination_ipv4),
            .destination_port = ntohs(header.destination_port),
        }
    );
    if (!candidate)
        return;

    auto _ = store_.store(
        *candidate,
        cache::CacheTime(std::chrono::nanoseconds(header.response_observed_at_ns)),
        time_source_()
    );
}

} // namespace shinku::backend::ebpf
