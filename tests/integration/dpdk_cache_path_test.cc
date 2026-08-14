// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/dpdk/dpdk_cache_store.h"
#include "backend/dpdk/dpdk_hash_table.h"
#include "backend/dpdk/dpdk_packet_path.h"
#include "backend/dpdk/dpdk_pending_store.h"
#include "backend/dpdk/dpdk_port.h"
#include "cache/dns_policy.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <memory>
#include <print>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

using shinku::backend::dpdk::DnsPacketDirection;
using shinku::backend::dpdk::DpdkDescriptorCounts;
using shinku::backend::dpdk::DpdkError;
using shinku::backend::dpdk::DpdkPort;
using Frame = std::vector<std::byte>;
using namespace std::chrono_literals;

constexpr size_t kDnsOffset = 14 + 20 + 8;
constexpr size_t kDnsQuestionOffset = 12;
constexpr size_t kDnsTtlOffset = 35;

void write_u16(Frame& bytes, size_t offset, uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 1] = static_cast<std::byte>(value);
}

void write_u32(Frame& bytes, size_t offset, uint32_t value) {
    bytes[offset] = static_cast<std::byte>(value >> 24U);
    bytes[offset + 1] = static_cast<std::byte>(value >> 16U);
    bytes[offset + 2] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 3] = static_cast<std::byte>(value);
}

uint16_t read_u16(std::span<const std::byte> bytes, size_t offset) {
    return static_cast<uint16_t>(static_cast<uint16_t>(std::to_integer<uint8_t>(bytes[offset])) << 8U)
        | std::to_integer<uint8_t>(bytes[offset + 1]);
}

uint32_t read_u32(std::span<const std::byte> bytes, size_t offset) {
    return static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset])) << 24U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset + 1])) << 16U
        | static_cast<uint32_t>(std::to_integer<uint8_t>(bytes[offset + 2])) << 8U
        | std::to_integer<uint8_t>(bytes[offset + 3]);
}

Frame question(bool uppercase) {
    Frame result {
        std::byte { 7 },   static_cast<std::byte>(uppercase ? 'E' : 'e'),
        std::byte { 'x' }, std::byte { 'a' },
        std::byte { 'm' }, std::byte { 'p' },
        std::byte { 'l' }, std::byte { 'e' },
        std::byte { 3 },   std::byte { 'c' },
        std::byte { 'o' }, std::byte { 'm' },
        std::byte { 0 },   std::byte { 0 },
        std::byte { 1 },   std::byte { 0 },
        std::byte { 1 },
    };
    return result;
}

Frame query(uint16_t transaction_id, bool uppercase) {
    Frame result(12);
    write_u16(result, 0, transaction_id);
    write_u16(result, 2, 0x0100);
    write_u16(result, 4, 1);
    const Frame encoded_question = question(uppercase);
    result.insert(result.end(), encoded_question.begin(), encoded_question.end());
    return result;
}

Frame response(uint16_t transaction_id) {
    Frame result(12);
    write_u16(result, 0, transaction_id);
    write_u16(result, 2, 0x8180);
    write_u16(result, 4, 1);
    write_u16(result, 6, 1);
    const Frame encoded_question = question(false);
    result.insert(result.end(), encoded_question.begin(), encoded_question.end());
    result.push_back(std::byte { 0xc0 });
    result.push_back(std::byte { 0x0c });
    const size_t record_fields = result.size();
    result.resize(record_fields + 10 + 4);
    write_u16(result, record_fields, 1);
    write_u16(result, record_fields + 2, 1);
    write_u32(result, record_fields + 4, 60);
    write_u16(result, record_fields + 8, 4);
    result[record_fields + 10] = std::byte { 203 };
    result[record_fields + 11] = std::byte { 0 };
    result[record_fields + 12] = std::byte { 113 };
    result[record_fields + 13] = std::byte { 7 };
    return result;
}

Frame udp_frame(bool from_client, std::span<const std::byte> dns) {
    Frame frame(kDnsOffset + dns.size());
    const std::array<std::byte, 6> client_mac {
        std::byte { 0x02 }, std::byte { 0x00 }, std::byte { 0x00 },
        std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x01 },
    };
    const std::array<std::byte, 6> service_mac {
        std::byte { 0x02 }, std::byte { 0x00 }, std::byte { 0x00 },
        std::byte { 0x00 }, std::byte { 0x00 }, std::byte { 0x02 },
    };
    const auto& source_mac = from_client ? client_mac : service_mac;
    const auto& destination_mac = from_client ? service_mac : client_mac;
    std::memcpy(frame.data(), destination_mac.data(), destination_mac.size());
    std::memcpy(frame.data() + 6, source_mac.data(), source_mac.size());
    write_u16(frame, 12, 0x0800);

    frame[14] = std::byte { 0x45 };
    write_u16(frame, 16, static_cast<uint16_t>(20 + 8 + dns.size()));
    write_u16(frame, 20, 0x4000);
    frame[22] = std::byte { 64 };
    frame[23] = std::byte { 17 };
    const uint32_t client_ipv4 = 0xc0000201U;
    const uint32_t service_ipv4 = 0xc6336402U;
    write_u32(frame, 26, from_client ? client_ipv4 : service_ipv4);
    write_u32(frame, 30, from_client ? service_ipv4 : client_ipv4);

    write_u16(frame, 34, from_client ? 53000 : 53);
    write_u16(frame, 36, from_client ? 53 : 53000);
    write_u16(frame, 38, static_cast<uint16_t>(8 + dns.size()));
    std::memcpy(frame.data() + kDnsOffset, dns.data(), dns.size());
    return frame;
}

class FakePort final: public DpdkPort {
public:
    explicit FakePort(std::string identity): identity_(std::move(identity)) {}
    std::deque<rte_mbuf*> incoming;
    std::vector<rte_mbuf*> transmitted;

    std::expected<DpdkDescriptorCounts, DpdkError> configure() override {
        return DpdkDescriptorCounts { .rx = 32, .tx = 32 };
    }

    std::expected<void, DpdkError> setup_queues(int) override {
        return {};
    }

    std::expected<void, DpdkError> start() override {
        return {};
    }

    void log_link_state() const noexcept override {}

    uint16_t receive(std::span<rte_mbuf*> packets) noexcept override {
        const auto count = static_cast<uint16_t>(std::min<size_t>(incoming.size(), packets.size()));
        for (uint16_t packet = 0; packet < count; ++packet) {
            packets[packet] = incoming.front();
            incoming.pop_front();
        }
        return count;
    }

    uint16_t transmit(std::span<rte_mbuf*> packets) noexcept override {
        transmitted.insert(transmitted.end(), packets.begin(), packets.end());
        return static_cast<uint16_t>(packets.size());
    }

    void free_packet(rte_mbuf&) noexcept override {}

    std::string_view identity() const noexcept override {
        return identity_;
    }

    bool owns_resources() const noexcept override {
        return false;
    }

    std::expected<void, DpdkError> close() override {
        return {};
    }

private:
    std::string identity_;
};

rte_mbuf* packet(rte_mempool* pool, std::span<const std::byte> frame) {
    rte_mbuf* result = rte_pktmbuf_alloc(pool);
    if (result == nullptr)
        return nullptr;
    void* destination = rte_pktmbuf_append(result, static_cast<uint16_t>(frame.size()));
    if (destination == nullptr) {
        rte_pktmbuf_free(result);
        return nullptr;
    }
    std::memcpy(destination, frame.data(), frame.size());
    return result;
}

shinku::cache::CacheKey cache_key(uint8_t label, uint16_t type = 1) {
    const std::array wire { std::byte { 1 }, static_cast<std::byte>(label), std::byte { 0 } };
    auto name = shinku::cache::CanonicalDnsName::from_wire(wire);
    return {
        .cache_namespace = { .destination_ipv4 = 0xc6336402U, .destination_port = 53 },
        .question_name = *name,
        .question_type = type,
        .question_class = 1,
    };
}

std::expected<shinku::cache::StoreOutcome, shinku::cache::CacheStoreError> store_candidate(
    shinku::backend::dpdk::DpdkCacheStore& store,
    const shinku::cache::CacheKey& key,
    shinku::cache::CacheTime observed_at,
    shinku::cache::CacheTime now,
    std::chrono::seconds lifetime = 60s,
    std::byte marker = std::byte { 1 }
) {
    const std::array response { marker };
    const std::array<uint16_t, 0> offsets {};
    const shinku::cache::CacheCandidate candidate {
        .key = key,
        .kind = shinku::cache::CacheEntryKind::Positive,
        .lifetime = lifetime,
        .response = response,
        .ttl_offsets = offsets,
    };
    return store.store(candidate, observed_at, now);
}

shinku::backend::dpdk::DpdkPendingKey pending_key(uint16_t transaction_id) {
    return {
        .source_ipv4 = 0x010200c0U,
        .destination_ipv4 = 0x026433c6U,
        .source_port = 0x08cfU,
        .destination_port = 0x3500U,
        .transaction_id = transaction_id,
    };
}

shinku::cache::dns::DnsQuestion pending_question(uint8_t label) {
    const std::array wire_name { std::byte { 1 }, static_cast<std::byte>(label), std::byte { 0 } };
    auto name = shinku::cache::CanonicalDnsName::from_wire(wire_name);
    assert(name.has_value());
    return { .name = *name, .type = 1, .class_code = 1 };
}

bool run_store_contracts() {
    bool passed = true;
    const auto check = [&](bool condition, std::string_view message) {
        if (!condition) {
            std::println(stderr, "DPDK store contract failed: {}", message);
            passed = false;
        }
    };
    const shinku::cache::CacheTime start(100s);

    {
        auto hash = shinku::backend::dpdk::DpdkHashTable<uint32_t, uint32_t>::create(
            "shinku-dpdk-hash-contract",
            1,
            SOCKET_ID_ANY
        );
        check(hash.has_value(), "hash table creation");
        if (!hash)
            return false;
        const uint32_t key = 7;
        uint32_t value = 11;
        auto missing = hash->lookup(key);
        check(missing && *missing == nullptr, "hash missing lookup");
        check(hash->insert(key, value).has_value(), "hash insert");
        auto found = hash->lookup(key);
        check(found && *found == &value, "hash value lookup");
        check(hash->erase(key).has_value(), "hash erase");
        auto erased = hash->lookup(key);
        check(erased && *erased == nullptr, "hash erased lookup");
        auto missing_erase = hash->erase(key);
        check(
            !missing_erase && missing_erase.error() == std::errc::no_such_file_or_directory,
            "hash erase return code"
        );
    }

    {
        auto store = shinku::backend::dpdk::DpdkCacheStore::create(2, 512, SOCKET_ID_ANY);
        check(store.has_value(), "cache creation");
        if (!store)
            return false;
        const auto first_key = cache_key('a');
        const auto second_key = cache_key('b');
        const auto third_key = cache_key('c');
        auto first = store_candidate(**store, first_key, start, start);
        auto second = store_candidate(**store, second_key, start, start);
        check(first == shinku::cache::StoreOutcome::Inserted, "first insert");
        check(second == shinku::cache::StoreOutcome::Inserted, "second insert");
        const auto* first_address = (*store)->lookup(first_key, start);
        auto updated = store_candidate(**store, first_key, start + 1s, start + 1s, 60s, std::byte { 2 });
        check(updated == shinku::cache::StoreOutcome::Updated, "same-key update");
        check((*store)->lookup(first_key, start + 1s) == first_address, "update pointer stability");
        auto replaced = store_candidate(**store, third_key, start + 2s, start + 2s);
        check(replaced == shinku::cache::StoreOutcome::Replaced, "round-robin replacement");
        check((*store)->lookup(first_key, start + 2s) == nullptr, "victim unpublished");
        check((*store)->lookup(third_key, start + 2s) != nullptr, "replacement visible");
    }

    {
        auto store = shinku::backend::dpdk::DpdkCacheStore::create(1, 128, SOCKET_ID_ANY);
        check(store.has_value(), "configured admission store creation");
        if (!store)
            return false;
        const std::array<std::byte, 129> response {};
        const std::array<uint16_t, 0> offsets {};
        const shinku::cache::CacheCandidate candidate {
            .key = cache_key('z'),
            .kind = shinku::cache::CacheEntryKind::Positive,
            .lifetime = 60s,
            .response = response,
            .ttl_offsets = offsets,
        };
        auto rejected = (*store)->store(candidate, start, start);
        check(rejected == shinku::cache::StoreOutcome::Rejected, "configured response admission limit");
    }

    {
        auto store = shinku::backend::dpdk::DpdkCacheStore::create(33, 512, SOCKET_ID_ANY);
        check(store.has_value(), "cleanup store creation");
        if (!store)
            return false;
        auto inserted = store_candidate(**store, cache_key('x'), start, start, 1s);
        check(inserted == shinku::cache::StoreOutcome::Inserted, "cleanup seed");
        auto first_batch = (*store)->cleanup(start + 1s);
        auto second_batch = (*store)->cleanup(start + 1s);
        check(first_batch && first_batch->removed_entries == 1 && first_batch->more_work, "32-entry cleanup batch");
        check(second_batch && second_batch->removed_entries == 0 && !second_batch->more_work, "cleanup completion");
    }

    {
        auto store = shinku::backend::dpdk::DpdkPendingStore::create(1, SOCKET_ID_ANY);
        check(store.has_value(), "pending creation");
        if (!store)
            return false;
        const auto first_key = pending_key(0x3412U);
        const auto second_key = pending_key(0x7856U);
        const auto first_question = pending_question('a');
        const auto second_question = pending_question('b');
        check(
            (*store)->remember(first_key, first_question, start)
                == shinku::backend::dpdk::DpdkPendingStoreResult::Inserted,
            "pending insert"
        );
        check(
            (*store)->remember(first_key, first_question, start + 2s)
                == shinku::backend::dpdk::DpdkPendingStoreResult::Refreshed,
            "active retransmission refresh after timeout"
        );
        check(
            (*store)->remember(first_key, second_question, start + 2s)
                == shinku::backend::dpdk::DpdkPendingStoreResult::Skipped,
            "question mismatch retention"
        );
        check(
            (*store)->remember(second_key, first_question, start + 2s)
                == shinku::backend::dpdk::DpdkPendingStoreResult::Skipped,
            "capacity fail-open"
        );
        auto mismatch = (*store)->claim(first_key, second_question, start + 2s, 1s);
        check(mismatch && !*mismatch, "mismatch does not claim");
        auto claimed = (*store)->claim(first_key, first_question, start + 2s, 1s);
        check(claimed && *claimed, "active claim");
        auto duplicate = (*store)->claim(first_key, first_question, start + 2s, 1s);
        check(duplicate && !*duplicate, "claimed tombstone suppresses duplicate");
        auto cleanup = (*store)->cleanup(start + 3s, 1s);
        check(cleanup && cleanup->removed_entries == 1, "claimed tombstone cleanup");
        check(
            (*store)->remember(second_key, first_question, start + 3s)
                == shinku::backend::dpdk::DpdkPendingStoreResult::Inserted,
            "cleanup restores pending capacity"
        );
    }
    return passed;
}

bool initialize_eal(int argc, char** argv) {
    return rte_eal_init(argc, argv) >= 0;
}

bool run_cache_path() {
    rte_mempool* pool =
        rte_pktmbuf_pool_create("shinku-9b-packets", 255, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    if (pool == nullptr) {
        std::println(stderr, "DPDK cache path setup failed: packet pool: {}", rte_strerror(rte_errno));
        return false;
    }

    bool passed = true;
    const auto check = [&](bool condition, std::string_view message) {
        if (!condition) {
            std::println(stderr, "DPDK cache path check failed: {}", message);
            passed = false;
        }
    };
    std::array<rte_mbuf*, 3> owned {};
    {
        auto cache = shinku::backend::dpdk::DpdkCacheStore::create(4, 512, SOCKET_ID_ANY);
        auto pending = shinku::backend::dpdk::DpdkPendingStore::create(4, SOCKET_ID_ANY);
        if (!cache || !pending) {
            std::println(stderr, "DPDK cache path setup failed: hash stores");
            rte_mempool_free(pool);
            return false;
        }
        shinku::cache::DnsPolicy policy(512, true);
        shinku::backend::dpdk::DpdkCacheContext context {
            .cache = **cache,
            .pending = **pending,
            .policy = policy,
            .pending_timeout = std::chrono::seconds(1),
            .cache_cleanup_interval = std::chrono::seconds(1),
        };
        FakePort client_port("test-client");
        FakePort service_port("test-service");
        shinku::backend::dpdk::DpdkPacketForwarder
            client(client_port, service_port, DnsPacketDirection::Query, context);
        shinku::backend::dpdk::DpdkPacketForwarder
            service(service_port, client_port, DnsPacketDirection::Response, context);

        const Frame first_query = udp_frame(true, query(0x1234, false));
        const Frame first_response = udp_frame(false, response(0x1234));
        owned[0] = packet(pool, first_query);
        owned[1] = packet(pool, first_response);
        if (owned[0] == nullptr || owned[1] == nullptr) {
            std::println(stderr, "DPDK cache path setup failed: initial mbufs");
            passed = false;
        } else {
            client_port.incoming.push_back(owned[0]);
            service_port.incoming.push_back(owned[1]);
            check(client.run().has_value(), "query miss quantum");
            check(service.run().has_value(), "response fill quantum");
            check(service_port.transmitted == std::vector<rte_mbuf*> { owned[0] }, "query forwarded to service");
            check(client_port.transmitted == std::vector<rte_mbuf*> { owned[1] }, "response forwarded to client");
        }

        const Frame second_query = udp_frame(true, query(0x5678, true));
        owned[2] = packet(pool, second_query);
        if (owned[2] == nullptr) {
            std::println(stderr, "DPDK cache path setup failed: hit mbuf");
            passed = false;
        } else {
            client_port.incoming.push_back(owned[2]);
            check(client.run().has_value(), "hit quantum");
            check(service_port.transmitted.size() == 1, "hit did not reach service");
            check(
                client_port.transmitted.size() == 2 && client_port.transmitted[1] == owned[2],
                "hit returned query mbuf to client"
            );

            const auto bytes =
                std::span(rte_pktmbuf_mtod(owned[2], const std::byte*), static_cast<size_t>(owned[2]->data_len));
            const Frame expected_question = question(true);
            check(bytes.size() == kDnsOffset + response(0).size(), "hit frame length");
            check(read_u16(bytes, kDnsOffset) == 0x5678, "hit transaction ID");
            check(
                std::memcmp(
                    bytes.data() + kDnsOffset + kDnsQuestionOffset,
                    expected_question.data(),
                    expected_question.size()
                ) == 0,
                "hit question bytes"
            );
            check(read_u32(bytes, kDnsOffset + kDnsTtlOffset) == 60, "hit TTL");
            check(read_u16(bytes, 40) == 0, "hit UDP checksum");
            check(owned[2]->packet_type == 0 && owned[2]->tx_offload == 0, "hit scalar metadata");
            check((owned[2]->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK) == 0, "hit offload flags");
        }
    }

    for (rte_mbuf* owned_packet: owned) {
        if (owned_packet != nullptr)
            rte_pktmbuf_free(owned_packet);
    }
    rte_mempool_free(pool);
    return passed;
}

} // namespace

int main(int argc, char** argv) {
    if (!initialize_eal(argc, argv)) {
        std::println(stderr, "DPDK cache path EAL initialization failed");
        return 1;
    }
    const bool passed = run_store_contracts() && run_cache_path();
    const int cleanup_result = rte_eal_cleanup();
    if (cleanup_result < 0)
        std::println(stderr, "DPDK cache path teardown failed: EAL cleanup");
    if (!passed || cleanup_result < 0) {
        std::println(stderr, "DPDK cache path smoke failed");
        return 1;
    }
    std::println("DPDK cache path smoke passed: miss, correlation, fill, and hit");
    return 0;
}
