// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "backend/ebpf/cache/ebpf_cache_storage_layout.h"
#include "backend/ebpf/cache/ebpf_cache_store.h"
#include "cache/cache_candidate.h"
#include "cache/cache_time.h"
#include "config/config.h"
#include "ebpf_cache_abi.h"
#include "ebpf_cache_verifier.skel.h"

#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <print>
#include <span>
#include <unistd.h>

namespace {

using shinku::backend::ebpf::EbpfCacheStore;
using shinku::backend::ebpf::EbpfNativeStorageBinding;
using shinku::backend::ebpf::make_ebpf_cache_storage_layout;

shinku::cache::CacheTime boot_time() {
    timespec value {};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0)
        return {};
    const auto nanoseconds = std::chrono::seconds(value.tv_sec) + std::chrono::nanoseconds(value.tv_nsec);
    return shinku::cache::CacheTime(nanoseconds);
}

int run_cross_boundary_hit(ebpf_cache_verifier_bpf* skeleton) {
    auto config = shinku::config::CacheConfig::create({
        .max_entries = 16,
        .max_response_bytes = 512,
        .cache_negative = true,
        .max_pending_queries = 16,
        .pending_query_timeout = std::chrono::seconds(1),
    });
    if (!config) {
        std::println(stderr, "failed to construct verifier config");
        return 1;
    }
    auto layout = make_ebpf_cache_storage_layout(*config, 4096);
    if (!layout) {
        std::println(stderr, "failed to calculate verifier layout");
        return 1;
    }

    auto store = EbpfCacheStore::create(
        *layout,
        EbpfNativeStorageBinding(
            bpf_map__fd(skeleton->maps.verifier_cache_map),
            std::as_writable_bytes(std::span(skeleton->arena->verifier_slots))
        ),
        skeleton->rodata->verifier_secret
    );
    if (!store) {
        std::println(stderr, "failed to construct verifier Store: {}", store.error().message());
        return 1;
    }

    const std::array question_name {
        std::byte { 12 },  std::byte { 'v' }, std::byte { 'e' }, std::byte { 'r' }, std::byte { 'i' },
        std::byte { 'f' }, std::byte { 'i' }, std::byte { 'e' }, std::byte { 'r' }, std::byte { 't' },
        std::byte { 'e' }, std::byte { 's' }, std::byte { 't' }, std::byte { 0 },
    };
    auto canonical_name = shinku::cache::CanonicalDnsName::from_wire(question_name);
    if (!canonical_name)
        return 1;

    std::array<std::byte, 32> response {};
    response[12] = std::byte { 0 };
    response[13] = std::byte { 0 };
    response[14] = std::byte { 1 };
    response[15] = std::byte { 44 }; // 300 seconds in network order.
    const std::array<uint16_t, 1> ttl_offsets { 12 };
    const shinku::cache::CacheCandidate candidate {
        .key = {
            .cache_namespace = { .destination_ipv4 = 0, .destination_port = 0 },
            .question_name = *canonical_name,
            .question_type = 1,
            .question_class = 1,
        },
        .kind = shinku::cache::CacheEntryKind::Positive,
        .lifetime = std::chrono::seconds(30),
        .response = response,
        .ttl_offsets = ttl_offsets,
    };
    auto stored = (*store)->store(candidate, boot_time());
    if (!stored) {
        std::println(stderr, "failed to write verifier candidate");
        return 1;
    }

    std::array<unsigned char, 512> output {};
    bpf_test_run_opts options {};
    options.sz = sizeof(options);
    options.data_in = question_name.data();
    options.data_out = output.data();
    options.data_size_in = question_name.size();
    options.data_size_out = output.size();
    const int result = bpf_prog_test_run_opts(bpf_program__fd(skeleton->progs.combined_hit_verifier), &options);
    if (result != 0 || options.retval != XDP_TX || options.data_size_out != response.size()) {
        std::println(
            stderr,
            "combined verifier run failed: syscall={} retval={} output={}",
            result,
            options.retval,
            options.data_size_out
        );
        return 1;
    }
    return 0;
}

} // namespace

int main() {
    if (geteuid() != 0) {
        std::println(stderr, "SKIP: loading the verifier gate requires root");
        return 77;
    }

    ebpf_cache_verifier_bpf* skeleton = ebpf_cache_verifier_bpf__open_and_load();
    if (skeleton == nullptr) {
        std::println(stderr, "failed to load the Module 8D verifier gate");
        return 1;
    }

    const int result = run_cross_boundary_hit(skeleton);
    ebpf_cache_verifier_bpf__destroy(skeleton);
    return result;
}
