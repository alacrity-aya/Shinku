// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "cache.skel.h"
#include "config/config.h"
#include "ebpf_cache_abi.h"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <print>
#include <span>
#include <unistd.h>
#include <vector>

namespace {

constexpr size_t kEthernetBytes = 14;
constexpr size_t kIpv4Bytes = 20;
constexpr size_t kUdpBytes = 8;
constexpr size_t kDnsOffset = kEthernetBytes + kIpv4Bytes + kUdpBytes;
constexpr std::array<unsigned char, 13> kQname { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

int verifier_log(libbpf_print_level level, const char* format, va_list args) noexcept {
    if (level == LIBBPF_DEBUG)
        return 0;
    return std::vfprintf(stderr, format, args);
}

int configure_and_load(cache_bpf* skeleton) {
    auto config = shinku::config::CacheConfig::create({
        .max_entries = 16,
        .max_response_bytes = 512,
        .cache_negative = true,
        .max_pending_queries = 32,
        .pending_query_timeout = std::chrono::seconds(2),
    });
    if (!config) {
        std::println(stderr, "failed to construct production verifier config");
        return 1;
    }

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        std::println(stderr, "failed to read page size");
        return 1;
    }
    const auto layout = shinku::backend::ebpf::make_ebpf_cache_storage_layout(*config, static_cast<size_t>(page_size));

    skeleton->rodata->shinku_config = {
        .cache_layout = layout.bpf_layout(),
        .secret = { .first = 0x0123'4567'89ab'cdefULL, .second = 0xfedc'ba98'7654'3210ULL },
        .pending_timeout_ns = 2'000'000'000ULL,
    };
    int result = bpf_map__set_max_entries(skeleton->maps.arena, layout.arena_page_count);
    if (result == 0)
        result = bpf_map__set_max_entries(skeleton->maps.cache_map, layout.entry_capacity);
    if (result == 0)
        result = bpf_map__set_max_entries(skeleton->maps.pending_queries, config->max_pending_queries());
    if (result != 0) {
        std::println(stderr, "failed to configure production maps: {}", -result);
        return 1;
    }

    result = cache_bpf__load(skeleton);
    if (result != 0) {
        std::println(stderr, "failed to load production 8E programs: {}", -result);
        return 1;
    }
    if (bpf_program__fd(skeleton->progs.xdp_rx) < 0 || bpf_program__fd(skeleton->progs.tc_tx) < 0
        || skeleton->arena == nullptr)
    {
        std::println(stderr, "production skeleton binding is incomplete after load");
        return 1;
    }
    return 0;
}

std::vector<unsigned char> make_dns_packet(bool query, bool multicast = false) {
    constexpr size_t dns_header_bytes = 12;
    constexpr size_t dns_bytes = dns_header_bytes + kQname.size() + 4;
    std::vector<unsigned char> packet(kEthernetBytes + kIpv4Bytes + kUdpBytes + dns_bytes);
    std::fill(packet.begin(), packet.begin() + kEthernetBytes, 0);
    packet[0] = multicast ? 1 : 2;
    packet[5] = 2;
    packet[6] = 2;
    packet[11] = 1;
    packet[12] = 0x08;
    packet[13] = 0x00;
    const size_t ip = kEthernetBytes;
    packet[ip] = 0x45;
    const uint16_t ip_length = htons(static_cast<uint16_t>(kIpv4Bytes + kUdpBytes + dns_bytes));
    std::memcpy(packet.data() + ip + 2, &ip_length, sizeof(ip_length));
    packet[ip + 8] = 64;
    packet[ip + 9] = 17;
    const uint32_t source = htonl(query ? 0x0a000001U : 0x0a000002U);
    const uint32_t destination = htonl(query ? 0x0a000002U : 0x0a000001U);
    std::memcpy(packet.data() + ip + 12, &source, sizeof(source));
    std::memcpy(packet.data() + ip + 16, &destination, sizeof(destination));
    const size_t udp = ip + kIpv4Bytes;
    const uint16_t source_port = htons(query ? 40000 : 53);
    const uint16_t destination_port = htons(query ? 53 : 40000);
    std::memcpy(packet.data() + udp, &source_port, sizeof(source_port));
    std::memcpy(packet.data() + udp + 2, &destination_port, sizeof(destination_port));
    const uint16_t udp_length = htons(static_cast<uint16_t>(kUdpBytes + dns_bytes));
    std::memcpy(packet.data() + udp + 4, &udp_length, sizeof(udp_length));
    const size_t dns = udp + kUdpBytes;
    const uint16_t transaction_id = htons(0x1234);
    const uint16_t flags = htons(query ? 0x0100 : 0x8100);
    const uint16_t one = htons(1);
    std::memcpy(packet.data() + dns, &transaction_id, sizeof(transaction_id));
    std::memcpy(packet.data() + dns + 2, &flags, sizeof(flags));
    std::memcpy(packet.data() + dns + 4, &one, sizeof(one));
    if (!query)
        std::memcpy(packet.data() + dns + 6, &one, sizeof(one));
    std::memcpy(packet.data() + dns + 12, kQname.data(), kQname.size());
    const uint16_t qtype = htons(1);
    const uint16_t qclass = htons(1);
    std::memcpy(packet.data() + dns + 12 + kQname.size(), &qtype, sizeof(qtype));
    std::memcpy(packet.data() + dns + 12 + kQname.size() + 2, &qclass, sizeof(qclass));
    return packet;
}

std::vector<unsigned char> make_dns_response_template() {
    const auto packet = make_dns_packet(false);
    std::vector<unsigned char> response(packet.begin() + kDnsOffset, packet.end());
    const std::array<unsigned char, 16> answer {
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x09,
    };
    response.insert(response.end(), answer.begin(), answer.end());
    return response;
}

uint64_t boot_time_ns() {
    timespec now {};
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0)
        return 0;
    return static_cast<uint64_t>(now.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(now.tv_nsec);
}

struct EventCapture {
    size_t count = 0;
    bool invalid_size = false;
    ebpf_correlated_dns_event event {};
};

int capture_event(void* opaque, void* data, size_t size) {
    auto& capture = *static_cast<EventCapture*>(opaque);
    ++capture.count;
    if (size != sizeof(capture.event)) {
        capture.invalid_size = true;
        return 0;
    }
    std::memcpy(&capture.event, data, sizeof(capture.event));
    return 0;
}

bool valid_ipv4_checksum(std::span<const unsigned char> header) {
    uint32_t sum = 0;
    for (size_t index = 0; index < header.size(); index += 2)
        sum += static_cast<uint16_t>((static_cast<uint16_t>(header[index]) << 8U) | header[index + 1]);
    while (sum > 0xffffU)
        sum = (sum & 0xffffU) + (sum >> 16U);
    return sum == 0xffffU;
}

uint32_t read_network_u32(std::span<const unsigned char> bytes, size_t offset) {
    uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return ntohl(value);
}

int install_cache_entry(cache_bpf* skeleton, const ebpf_cache_fingerprint& fingerprint) {
    const auto response = make_dns_response_template();
    const auto layout = skeleton->rodata->shinku_config.cache_layout;
    if (layout.slot_stride < sizeof(ebpf_cache_slot_header) + response.size() + sizeof(uint16_t))
        return 1;
    auto* slot = skeleton->arena->cache_slots;
    std::memset(slot, 0, layout.slot_stride);
    const uint64_t now = boot_time_ns();
    if (now < 1'500'000'000ULL)
        return 1;
    const ebpf_cache_slot_header header {
        .sequence = 0,
        .response_size = static_cast<uint16_t>(response.size()),
        .ttl_offset_count = 1,
        .generation = 7,
        .stored_at_ns = now - 1'500'000'000ULL,
        .expires_at_ns = now + 300'000'000'000ULL,
    };
    std::memcpy(slot, &header, sizeof(header));
    std::memcpy(slot + sizeof(header), response.data(), response.size());
    const size_t offset_table = (sizeof(header) + response.size() + 1U) & ~size_t { 1 };
    const uint16_t ttl_offset = 35;
    std::memcpy(slot + offset_table, &ttl_offset, sizeof(ttl_offset));

    const ebpf_cache_physical_key key {
        .destination_ipv4 = htonl(0x0a000002U),
        .destination_port = htons(53),
        .reserved = 0,
        .fingerprint = fingerprint,
    };
    const ebpf_cache_publication publication { .slot_index = 0, .reserved = 0, .generation = 7 };
    if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.cache_map), &key, &publication, BPF_ANY) != 0) {
        std::println(stderr, "failed to publish production Cache test entry: {}", errno);
        return 1;
    }
    return 0;
}

int run_production_program_paths(cache_bpf* skeleton) {
    const int pending_fd = bpf_map__fd(skeleton->maps.pending_queries);
    if (pending_fd < 0)
        return 1;

    auto query = make_dns_packet(true);
    bpf_test_run_opts query_opts {};
    query_opts.sz = sizeof(query_opts);
    query_opts.data_in = query.data();
    query_opts.data_size_in = query.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.xdp_rx), &query_opts) != 0
        || query_opts.retval != XDP_PASS)
    {
        std::println(stderr, "production Query test failed: syscall={} retval={}", errno, query_opts.retval);
        return 1;
    }

    ebpf_pending_query_key pending_key {
        .source_ipv4 = htonl(0x0a000001U),
        .destination_ipv4 = htonl(0x0a000002U),
        .source_port = htons(40000),
        .destination_port = htons(53),
        .transaction_id = htons(0x1234),
        .reserved = 0,
    };
    ebpf_pending_query_value pending_value {};
    if (bpf_map_lookup_elem(pending_fd, &pending_key, &pending_value) != 0
        || (pending_value.state_and_last_seen_ns & SHINKU_EBPF_PENDING_CLAIMED) != 0)
    {
        std::println(stderr, "production Query did not create Active Pending entry");
        return 1;
    }

    const auto first_seen = pending_value.state_and_last_seen_ns;
    query_opts = {};
    query_opts.sz = sizeof(query_opts);
    query_opts.data_in = query.data();
    query_opts.data_size_in = query.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.xdp_rx), &query_opts) != 0
        || query_opts.retval != XDP_PASS || bpf_map_lookup_elem(pending_fd, &pending_key, &pending_value) != 0
        || pending_value.state_and_last_seen_ns <= first_seen)
    {
        std::println(stderr, "production Query refresh test failed");
        return 1;
    }

    auto invalid = make_dns_packet(true, true);
    const ebpf_pending_query_key invalid_key {
        .source_ipv4 = htonl(0x0a000001U),
        .destination_ipv4 = htonl(0x0a000002U),
        .source_port = htons(40000),
        .destination_port = htons(53),
        .transaction_id = htons(0x5678),
        .reserved = 0,
    };
    const uint16_t invalid_id = htons(0x5678);
    std::memcpy(invalid.data() + kDnsOffset, &invalid_id, sizeof(invalid_id));
    bpf_test_run_opts invalid_opts {};
    invalid_opts.sz = sizeof(invalid_opts);
    invalid_opts.data_in = invalid.data();
    invalid_opts.data_size_in = invalid.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.xdp_rx), &invalid_opts) != 0
        || invalid_opts.retval != XDP_PASS)
    {
        std::println(
            stderr,
            "production invalid-envelope test failed: syscall={} retval={}",
            errno,
            invalid_opts.retval
        );
        return 1;
    }
    if (bpf_map_lookup_elem(pending_fd, &invalid_key, &pending_value) == 0) {
        std::println(stderr, "invalid envelope unexpectedly created Pending entry");
        return 1;
    }

    EventCapture capture {};
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring(
        ring_buffer__new(bpf_map__fd(skeleton->maps.rb_pkt), capture_event, &capture, nullptr),
        ring_buffer__free
    );
    if (!ring) {
        std::println(stderr, "failed to create production event ring consumer: {}", errno);
        return 1;
    }
    auto response = make_dns_packet(false);
    bpf_test_run_opts response_opts {};
    response_opts.sz = sizeof(response_opts);
    response_opts.data_in = response.data();
    response_opts.data_size_in = response.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.tc_tx), &response_opts) != 0
        || response_opts.retval != 0)
    {
        std::println(stderr, "production Response test failed: syscall={} retval={}", errno, response_opts.retval);
        return 1;
    }
    if (ring_buffer__consume(ring.get()) != 1 || capture.count != 1 || capture.invalid_size
        || capture.event.response_size
            != htons(static_cast<uint16_t>(response.size() - kEthernetBytes - kIpv4Bytes - kUdpBytes))
        || capture.event.destination_ipv4 != htonl(0x0a000002U) || capture.event.destination_port != htons(53)
        || std::memcmp(capture.event.response, response.data() + kDnsOffset, response.size() - kDnsOffset) != 0)
    {
        std::println(stderr, "production Response did not publish one valid correlated event");
        return 1;
    }
    if (bpf_map_lookup_elem(pending_fd, &pending_key, &pending_value) != 0
        || (pending_value.state_and_last_seen_ns & SHINKU_EBPF_PENDING_CLAIMED) == 0)
    {
        std::println(stderr, "production Response did not leave Claimed tombstone");
        return 1;
    }

    response_opts = {};
    response_opts.sz = sizeof(response_opts);
    response_opts.data_in = response.data();
    response_opts.data_size_in = response.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.tc_tx), &response_opts) != 0
        || response_opts.retval != 0)
    {
        std::println(
            stderr,
            "production duplicate Response test failed: syscall={} retval={}",
            errno,
            response_opts.retval
        );
        return 1;
    }
    if (ring_buffer__consume(ring.get()) != 0 || capture.count != 1) {
        std::println(stderr, "production duplicate Response published another event");
        return 1;
    }
    ebpf_pending_query_value duplicate_value {};
    if (bpf_map_lookup_elem(pending_fd, &pending_key, &duplicate_value) != 0
        || duplicate_value.state_and_last_seen_ns != pending_value.state_and_last_seen_ns)
    {
        std::println(stderr, "production duplicate Response changed Claimed tombstone");
        return 1;
    }

    if (install_cache_entry(skeleton, pending_value.fingerprint) != 0)
        return 1;
    auto hit_query = make_dns_packet(true);
    const uint16_t hit_id = htons(0xbeef);
    std::memcpy(hit_query.data() + kDnsOffset, &hit_id, sizeof(hit_id));
    hit_query[kDnsOffset + 13 + 1] = 'X';
    std::array<unsigned char, 1024> hit_output {};
    bpf_test_run_opts hit_opts {};
    hit_opts.sz = sizeof(hit_opts);
    hit_opts.data_in = hit_query.data();
    hit_opts.data_out = hit_output.data();
    hit_opts.data_size_in = hit_query.size();
    hit_opts.data_size_out = hit_output.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.xdp_rx), &hit_opts) != 0 || hit_opts.retval != XDP_TX
        || hit_opts.data_size_out != kDnsOffset + 45
        || std::memcmp(hit_output.data() + kDnsOffset, &hit_id, sizeof(hit_id)) != 0
        || hit_output[kEthernetBytes] != 0x45 || hit_output[kEthernetBytes + 1] != 0
        || hit_output[kEthernetBytes + 4] != 0 || hit_output[kEthernetBytes + 5] != 0
        || hit_output[kEthernetBytes + 6] != 0x40 || hit_output[kEthernetBytes + 7] != 0
        || hit_output[kEthernetBytes + 8] != 64
        || !valid_ipv4_checksum(std::span<const unsigned char>(hit_output).subspan(kEthernetBytes, kIpv4Bytes))
        || read_network_u32(std::span<const unsigned char>(hit_output), kDnsOffset + 35) >= 300
        || hit_output[kDnsOffset + 13 + 1] != 'X')
    {
        std::println(
            stderr,
            "production Cache Hit rewrite test failed: syscall={} retval={} output={}",
            errno,
            hit_opts.retval,
            hit_opts.data_size_out
        );
        return 1;
    }

    auto* cached_header = reinterpret_cast<ebpf_cache_slot_header*>(skeleton->arena->cache_slots);
    cached_header->expires_at_ns = boot_time_ns() - 1;
    auto expired_query = make_dns_packet(true);
    const uint16_t expired_id = htons(0xcafe);
    std::memcpy(expired_query.data() + kDnsOffset, &expired_id, sizeof(expired_id));
    bpf_test_run_opts expired_opts {};
    expired_opts.sz = sizeof(expired_opts);
    expired_opts.data_in = expired_query.data();
    expired_opts.data_size_in = expired_query.size();
    if (bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.xdp_rx), &expired_opts) != 0
        || expired_opts.retval != XDP_PASS)
    {
        std::println(stderr, "expired Cache publication did not fail open");
        return 1;
    }
    const ebpf_pending_query_key expired_key {
        .source_ipv4 = htonl(0x0a000001U),
        .destination_ipv4 = htonl(0x0a000002U),
        .source_port = htons(40000),
        .destination_port = htons(53),
        .transaction_id = expired_id,
        .reserved = 0,
    };
    if (bpf_map_lookup_elem(pending_fd, &expired_key, &pending_value) != 0
        || (pending_value.state_and_last_seen_ns & SHINKU_EBPF_PENDING_CLAIMED) != 0)
    {
        std::println(stderr, "expired Cache publication did not create Active Pending entry");
        return 1;
    }

    return 0;
}

} // namespace

int main() {
    if (geteuid() != 0) {
        std::println(stderr, "SKIP: loading production 8E programs requires root");
        return 77;
    }

    libbpf_set_print(verifier_log);
    cache_bpf* skeleton = cache_bpf__open();
    if (skeleton == nullptr) {
        std::println(stderr, "failed to open production 8E skeleton");
        return 1;
    }
    const int result = configure_and_load(skeleton);
    const int paths_result = result == 0 ? run_production_program_paths(skeleton) : result;
    cache_bpf__destroy(skeleton);
    return paths_result;
}
