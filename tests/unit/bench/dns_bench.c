#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef __BPF__
    #define __BPF__ 0
#endif

#include <linux/types.h>
#ifndef __be16
typedef uint16_t __be16;
#endif

#ifndef __always_inline
    #define __always_inline inline
#endif

#include "../../src/core/dns_parser.h"
#include "../../src/core/parser_runtime.h"
#include "../../src/include/constants.h"

#define BENCH_ITERATIONS 1000000
#define BENCH_WARMUP 10000
#define RECENT_BENCH_CAP 16384
#define RECENT_BUCKET_FACTOR 2

static double bench_ns(struct timespec* start, struct timespec* end) {
    return (double)(end->tv_sec - start->tv_sec) * 1e9 + (double)(end->tv_nsec - start->tv_nsec);
}

static void format_commas(double num, char* buf) {
    long long n = (long long)num;
    char temp[64];
    snprintf(temp, sizeof(temp), "%lld", n);
    int len = strlen(temp);
    int out_idx = 0;
    for (int i = 0; i < len; i++) {
        if (i > 0 && (len - i) % 3 == 0) {
            buf[out_idx++] = ',';
        }
        buf[out_idx++] = temp[i];
    }
    buf[out_idx] = '\0';
}

static __attribute__((noinline)) int
call_handle_packet(struct cache_context* cache_ctx, uint8_t* dns_pkt, uint32_t dns_len) {
    uint8_t buf[sizeof(struct dns_event) + 1500];
    memset(buf, 0, sizeof(buf));
    struct dns_event* event = (struct dns_event*)buf;
    struct dns_parser_context parser_ctx = { .cache = cache_ctx, .runtime = NULL };
    event->timestamp = 0;
    event->len = dns_len;
    memcpy(event->payload, dns_pkt, dns_len);
    return dns_parser_handle_event(&parser_ctx, event, sizeof(*event) + dns_len);
}

static void bench_hash_throughput(void) {
    // 1: www.example.com
    __u8 pkt1[] = { 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    uint32_t hash = 0;

    for (int i = 0; i < BENCH_WARMUP; i++) {
        calculate_hash_strict_impl(pkt1, 0, sizeof(pkt1), &hash);
    }

    struct timespec start, end;
    uint32_t sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint32_t h = 0;
        calculate_hash_strict_impl(pkt1, 0, sizeof(pkt1), &h);
        sum += h;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    volatile uint32_t sink = sum;
    (void)sink;

    double ns = bench_ns(&start, &end);
    double ms = ns / 1e6;
    double ops = (double)BENCH_ITERATIONS / (ns / 1e9);
    double lat = ns / (double)BENCH_ITERATIONS;

    char ops_str[32];
    format_commas(ops, ops_str);

    printf("\n[BENCH] Hash Throughput (www.example.com)\n");
    printf("  Iterations: %d\n", BENCH_ITERATIONS);
    printf("  Total: %.1fms\n", ms);
    printf("  Throughput: %s ops/sec\n", ops_str);
    printf("  Latency: %.1f ns/op\n", lat);

    // 2: very.long.subdomain.example.co.uk
    __u8 pkt2[] = { 0x04, 'v', 'e',  'r', 'y', 0x04, 'l', 'o', 'n', 'g', 0x09, 's', 'u', 'b',  'd', 'o', 'm', 'a',
                    'i',  'n', 0x07, 'e', 'x', 'a',  'm', 'p', 'l', 'e', 0x02, 'c', 'o', 0x02, 'u', 'k', 0x00 };

    for (int i = 0; i < BENCH_WARMUP; i++) {
        calculate_hash_strict_impl(pkt2, 0, sizeof(pkt2), &hash);
    }

    sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint32_t h = 0;
        calculate_hash_strict_impl(pkt2, 0, sizeof(pkt2), &h);
        sum += h;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    sink = sum;
    (void)sink;

    ns = bench_ns(&start, &end);
    ms = ns / 1e6;
    ops = (double)BENCH_ITERATIONS / (ns / 1e9);
    lat = ns / (double)BENCH_ITERATIONS;

    format_commas(ops, ops_str);

    printf("\n[BENCH] Hash Throughput (very.long.subdomain.example.co.uk)\n");
    printf("  Iterations: %d\n", BENCH_ITERATIONS);
    printf("  Total: %.1fms\n", ms);
    printf("  Throughput: %s ops/sec\n", ops_str);
    printf("  Latency: %.1f ns/op\n", lat);
}

static void bench_parse_throughput(void) {
    __u8 dns_resp[] = { 0x12, 0x34, // ID
                        0x81, 0x80, // Flags
                        0x00, 0x01, // QDCOUNT: 1
                        0x00, 0x01, // ANCOUNT: 1
                        0x00, 0x00, // NSCOUNT: 0
                        0x00, 0x00, // ARCOUNT: 0
                        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03,
                        'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };

    struct cache_context cache_ctx = { .entries = NULL, .next_idx = NULL, .max_entries = 0, .cache_map_fd = -1 };

    for (int i = 0; i < BENCH_WARMUP; i++) {
        call_handle_packet(&cache_ctx, dns_resp, sizeof(dns_resp));
    }

    struct timespec start, end;
    int sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        sum += call_handle_packet(&cache_ctx, dns_resp, sizeof(dns_resp));
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    volatile int sink = sum;
    (void)sink;

    double ns = bench_ns(&start, &end);
    double ms = ns / 1e6;
    double ops = (double)BENCH_ITERATIONS / (ns / 1e9);
    double lat = ns / (double)BENCH_ITERATIONS;

    char ops_str[32];
    format_commas(ops, ops_str);

    printf("\n[BENCH] Parse Throughput (A record, no store)\n");
    printf("  Iterations: %d\n", BENCH_ITERATIONS);
    printf("  Total: %.1fms\n", ms);
    printf("  Throughput: %s ops/sec\n", ops_str);
    printf("  Latency: %.1f ns/op\n", lat);
}

static uint64_t bench_key_fp(const struct cache_key* key) {
    const uint8_t* bytes = (const uint8_t*)key;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < sizeof(*key); i++) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static __attribute__((noinline)) int recent_lookup_legacy(
    const struct cache_key* keys,
    const uint64_t* ns,
    uint32_t cap,
    uint64_t window_ns,
    const struct cache_key* target,
    uint64_t now_ns
) {
    for (uint32_t i = 0; i < cap; i++) {
        if (ns[i] == 0)
            continue;
        if (memcmp(&keys[i], target, sizeof(*target)) != 0)
            continue;
        if (now_ns >= ns[i] && now_ns - ns[i] <= window_ns)
            return 1;
    }
    return 0;
}

static __attribute__((noinline)) int recent_lookup_bucketed(
    const struct cache_key* keys,
    const uint64_t* ns,
    uint32_t cap,
    uint64_t window_ns,
    const struct cache_key* target,
    uint64_t now_ns
) {
    uint32_t buckets = cap / RECENT_BUCKET_FACTOR;
    if (buckets == 0)
        return 0;

    uint64_t fp = bench_key_fp(target);
    uint32_t idx = (uint32_t)(fp % buckets);
    uint32_t start = idx * RECENT_BUCKET_FACTOR;
    uint32_t end = start + RECENT_BUCKET_FACTOR;
    for (uint32_t i = start; i < end; i++) {
        if (ns[i] == 0)
            continue;
        if (memcmp(&keys[i], target, sizeof(*target)) != 0)
            continue;
        if (now_ns >= ns[i] && now_ns - ns[i] <= window_ns)
            return 1;
    }
    return 0;
}

static void bench_name_parse_ab(void) {
    __u8 pkt[96] = { 0 };
    __u8 google_com[] = { 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    memcpy(&pkt[10], google_com, sizeof(google_com));
    pkt[30] = 0x04;
    memcpy(&pkt[31], "mail", 4);
    pkt[35] = 0xC0;
    pkt[36] = 0x0A;

    uint8_t flat[64] = { 0 };
    uint32_t hash = 0;
    int consumed = 0;

    for (int i = 0; i < BENCH_WARMUP; i++) {
        calculate_hash_strict_impl(pkt, 30, sizeof(pkt), &hash);
        flatten_name_impl(pkt, 30, sizeof(pkt), flat, sizeof(flat));
        calculate_hash_strict_impl(pkt, 30, sizeof(pkt), &hash);
    }

    struct timespec start, end;
    uint32_t sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        calculate_hash_strict_impl(pkt, 30, sizeof(pkt), &hash);
        int flat_len = flatten_name_impl(pkt, 30, sizeof(pkt), flat, sizeof(flat));
        int skip_len = calculate_hash_strict_impl(pkt, 30, sizeof(pkt), &hash);
        sum += hash + (uint32_t)flat_len + (uint32_t)skip_len;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    volatile uint32_t legacy_sink = sum;
    (void)legacy_sink;

    double legacy_ns = bench_ns(&start, &end);
    double legacy_lat = legacy_ns / (double)BENCH_ITERATIONS;

    for (int i = 0; i < BENCH_WARMUP; i++) {
        dns_parser_parse_name_impl(pkt, 30, sizeof(pkt), &hash, flat, sizeof(flat), &consumed);
    }

    sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        int flat_len = dns_parser_parse_name_impl(pkt, 30, sizeof(pkt), &hash, flat, sizeof(flat), &consumed);
        sum += hash + (uint32_t)flat_len + (uint32_t)consumed;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    volatile uint32_t opt_sink = sum;
    (void)opt_sink;

    double opt_ns = bench_ns(&start, &end);
    double opt_lat = opt_ns / (double)BENCH_ITERATIONS;

    printf("\n[BENCH] Name Parse A/B (legacy vs optimized)\n");
    printf("  Legacy (hash+flatten+skip): %.1f ns/op\n", legacy_lat);
    printf("  Optimized (single pass): %.1f ns/op\n", opt_lat);
    if (opt_lat > 0.0)
        printf("  Speedup: %.2fx\n", legacy_lat / opt_lat);
}

static void bench_recent_lookup_ab(void) {
    struct cache_key* keys = calloc(RECENT_BENCH_CAP, sizeof(struct cache_key));
    uint64_t* ns = calloc(RECENT_BENCH_CAP, sizeof(uint64_t));
    if (!keys || !ns) {
        free(keys);
        free(ns);
        return;
    }

    struct cache_key target = { CACHE_KEY_CORE_AND_ECS_INIT_DESIG(0x12345678, DNS_TYPE_A, 1, 0, 0, 0) };
    uint64_t now_ns = 1000000000ULL;
    uint64_t window_ns = 2000000000ULL;

    for (uint32_t i = 0; i < RECENT_BENCH_CAP; i++) {
        keys[i].name_hash = (uint32_t)(i + 1);
        keys[i].qtype = DNS_TYPE_A;
        keys[i].qclass = 1;
        ns[i] = now_ns - (uint64_t)(i % 31);
    }

    uint32_t buckets = RECENT_BENCH_CAP / RECENT_BUCKET_FACTOR;
    uint64_t fp = bench_key_fp(&target);
    uint32_t idx = (uint32_t)(fp % buckets);
    uint32_t pos = idx * RECENT_BUCKET_FACTOR;
    keys[pos] = target;
    ns[pos] = now_ns - 1;

    for (int i = 0; i < BENCH_WARMUP; i++) {
        recent_lookup_legacy(keys, ns, RECENT_BENCH_CAP, window_ns, &target, now_ns);
        recent_lookup_bucketed(keys, ns, RECENT_BENCH_CAP, window_ns, &target, now_ns);
    }

    struct timespec start, end;
    int found_sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        found_sum += recent_lookup_legacy(keys, ns, RECENT_BENCH_CAP, window_ns, &target, now_ns + (uint64_t)(i & 1));
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    volatile int legacy_sink = found_sum;
    (void)legacy_sink;
    double legacy_ns = bench_ns(&start, &end);
    double legacy_lat = legacy_ns / (double)BENCH_ITERATIONS;

    found_sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        found_sum += recent_lookup_bucketed(keys, ns, RECENT_BENCH_CAP, window_ns, &target, now_ns + (uint64_t)(i & 1));
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    volatile int opt_sink = found_sum;
    (void)opt_sink;
    double opt_ns = bench_ns(&start, &end);
    double opt_lat = opt_ns / (double)BENCH_ITERATIONS;

    printf("\n[BENCH] Recent Lookup A/B (linear vs bucketed)\n");
    printf("  Legacy (linear scan): %.1f ns/op\n", legacy_lat);
    printf("  Optimized (2-slot bucket): %.3f ns/op\n", opt_lat);
    if (opt_lat > 0.0)
        printf("  Speedup: %.2fx\n", legacy_lat / opt_lat);

    free(keys);
    free(ns);
}

static void bench_cache_store_throughput(void) {
    int fd = bpf_map_create(
        BPF_MAP_TYPE_HASH,
        "bench_map",
        sizeof(struct cache_key),
        sizeof(struct cache_value),
        16384,
        NULL
    );
    if (fd < 0) {
        printf("\n[BENCH] Cache Store Throughput (parse + store)\n");
        printf("  SKIPPED — BPF not available (need root)\n");
        return;
    }

    __u8 dns_resp[] = { 0x12, 0x34, // ID
                        0x81, 0x80, // Flags
                        0x00, 0x01, // QDCOUNT: 1
                        0x00, 0x01, // ANCOUNT: 1
                        0x00, 0x00, // NSCOUNT: 0
                        0x00, 0x00, // ARCOUNT: 0
                        0x03, 'w',  'w',  'w',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03,
                        'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };

    struct cache_entry* entries = malloc(16384 * sizeof(struct cache_entry));
    if (!entries) {
        close(fd);
        return;
    }

    uint32_t next_idx = 0;
    struct cache_context cache_ctx = { .entries = entries,
                                       .next_idx = &next_idx,
                                       .max_entries = 16384,
                                       .cache_map_fd = fd };

    int ITERATIONS = 100000;

    // Silence outputs from store_to_cache
    int fd_null = open("/dev/null", O_WRONLY);
    int saved_stdout = dup(1);
    int saved_stderr = dup(2);
    if (fd_null >= 0) {
        dup2(fd_null, 1);
        dup2(fd_null, 2);
    }

    struct timespec start, end;
    int sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        if (i % 16384 == 0) {
            next_idx = 0;
        }
        sum += call_handle_packet(&cache_ctx, dns_resp, sizeof(dns_resp));
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (fd_null >= 0) {
        dup2(saved_stdout, 1);
        dup2(saved_stderr, 2);
        close(fd_null);
    }
    close(saved_stdout);
    close(saved_stderr);

    close(fd);
    free(entries);

    volatile int sink = sum;
    (void)sink;

    double ns = bench_ns(&start, &end);
    double ms = ns / 1e6;
    double ops = (double)ITERATIONS / (ns / 1e9);
    double lat = ns / (double)ITERATIONS;

    char ops_str[32];
    format_commas(ops, ops_str);

    printf("\n[BENCH] Cache Store Throughput (parse + store)\n");
    printf("  Iterations: %d\n", ITERATIONS);
    printf("  Total: %.1fms\n", ms);
    printf("  Throughput: %s ops/sec\n", ops_str);
    printf("  Latency: %.1f ns/op\n", lat);
}

int main(void) {
    printf("========================================\n");
    printf("DNS Cache Benchmark Suite\n");
    printf("========================================\n");

    bench_hash_throughput();
    bench_parse_throughput();
    bench_cache_store_throughput();
    bench_name_parse_ab();
    bench_recent_lookup_ab();

    printf("\n========================================\n");
    printf("Benchmark complete.\n");
    printf("========================================\n");

    return 0;
}
