#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef __BPF__
    #define __BPF__ 0
#endif

#define DNS_CLASS_IN 1

typedef uint16_t __be16;

#ifndef __always_inline
    #define __always_inline inline
#endif

#include "../../src/include/constants.h"
#include "../../src/core/dns_parser.h"

static int test_count = 0;
static int pass_count = 0;

#define TEST_ASSERT(cond, msg, ...) \
    do { \
        test_count++; \
        if (cond) { \
            pass_count++; \
            printf("  [PASS] " msg "\n", ##__VA_ARGS__); \
        } else { \
            printf("  [FAIL] " msg "\n", ##__VA_ARGS__); \
        } \
    } while (0)

static int call_handle_packet(struct cache_ctx* cctx, uint8_t* dns_pkt, uint32_t dns_len) {
    uint8_t buf[sizeof(struct dns_event) + 1500];
    memset(buf, 0, sizeof(buf));
    struct dns_event* event = (struct dns_event*)buf;
    event->timestamp = 0;
    event->len = dns_len;
    memcpy(event->payload, dns_pkt, dns_len);
    return handle_packet(cctx, event, sizeof(*event) + dns_len);
}

static struct cache_ctx test_ctx;
static uint32_t test_next_idx = 0;
static struct cache_entry test_entries[10];
static int has_bpf = 0;

static void setup_test() {
    test_next_idx = 0;
    memset(test_entries, 0, sizeof(test_entries));
    test_ctx.entries = test_entries;
    test_ctx.next_idx = &test_next_idx;
    test_ctx.max_entries = 10;
}

struct dns_builder {
    uint8_t buf[1500];
    uint32_t len;
};

static void builder_init(struct dns_builder* b, uint16_t id, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    memset(b, 0, sizeof(*b));
    struct dns_hdr* hdr = (struct dns_hdr*)b->buf;
    hdr->id = htons(id);
    hdr->flags = htons(flags);
    hdr->qdcount = htons(qd);
    hdr->ancount = htons(an);
    hdr->nscount = htons(ns);
    hdr->arcount = htons(ar);
    b->len = sizeof(struct dns_hdr);
}

static void builder_add_name(struct dns_builder* b, const char* name) {
    if (name == NULL || *name == '\0') {
        b->buf[b->len++] = 0;
        return;
    }
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        int len = dot ? dot - p : strlen(p);
        b->buf[b->len++] = len;
        memcpy(b->buf + b->len, p, len);
        b->len += len;
        if (!dot) break;
        p = dot + 1;
    }
    b->buf[b->len++] = 0;
}

static void builder_add_question(struct dns_builder* b, const char* name, uint16_t qtype, uint16_t qclass) {
    builder_add_name(b, name);
    uint16_t* ptr = (uint16_t*)(b->buf + b->len);
    ptr[0] = htons(qtype);
    ptr[1] = htons(qclass);
    b->len += 4;
}

static void builder_add_answer(struct dns_builder* b, const char* name, uint16_t rtype, uint16_t rclass, uint32_t ttl, uint16_t rdlen, const uint8_t* rdata) {
    builder_add_name(b, name);
    uint16_t* ptr16 = (uint16_t*)(b->buf + b->len);
    ptr16[0] = htons(rtype);
    ptr16[1] = htons(rclass);
    b->len += 4;
    uint32_t* ptr32 = (uint32_t*)(b->buf + b->len);
    *ptr32 = htonl(ttl);
    b->len += 4;
    ptr16 = (uint16_t*)(b->buf + b->len);
    *ptr16 = htons(rdlen);
    b->len += 2;
    memcpy(b->buf + b->len, rdata, rdlen);
    b->len += rdlen;
}

/* --- Positive Tests --- */

// 1. test_simple_a_record
static void test_simple_a_record() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_simple_a_record: handle_packet returns 0");
    if (has_bpf) {
        TEST_ASSERT(test_next_idx == 1, "test_simple_a_record: next_idx incremented");
        TEST_ASSERT(test_entries[0].pkt[0] != 0, "test_simple_a_record: cache entry populated");
    } else {
        printf("  [SKIP] next_idx check for simple A record\n");
    }
}

// 2. test_simple_aaaa_record
static void test_simple_aaaa_record() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_AAAA, DNS_CLASS_IN);
    uint8_t aaaa_rdata[16] = {0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_AAAA, DNS_CLASS_IN, 600, 16, aaaa_rdata);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_simple_aaaa_record: handle_packet returns 0");
    if (has_bpf) {
        TEST_ASSERT(test_next_idx == 1, "test_simple_aaaa_record: next_idx incremented");
    }
}

// 3. test_multiple_a_records
static void test_multiple_a_records() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 2, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata1[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata1);
    uint8_t a_rdata2[4] = {5, 6, 7, 8};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, 60, 4, a_rdata2);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_multiple_a_records: handle_packet returns 0");
    if (has_bpf) {
        TEST_ASSERT(test_next_idx == 1, "test_multiple_a_records: next_idx incremented");
    }
}

// 4. test_min_ttl_selection
static void test_min_ttl_selection() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 3, 0, 0);
    builder_add_question(&b, "min.ttl.test", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t rdata[4] = {0,0,0,0};
    builder_add_answer(&b, "min.ttl.test", DNS_TYPE_A, DNS_CLASS_IN, 3600, 4, rdata);
    builder_add_answer(&b, "min.ttl.test", DNS_TYPE_A, DNS_CLASS_IN, 120, 4, rdata);
    builder_add_answer(&b, "min.ttl.test", DNS_TYPE_A, DNS_CLASS_IN, 1800, 4, rdata);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_min_ttl_selection: handle_packet returns 0");
    if (has_bpf) {
        TEST_ASSERT(test_next_idx == 1, "test_min_ttl_selection: next_idx incremented");
        // Verify TTL in cache_map by reading back from BPF map?
        // We only have bpf_map_lookup_elem if we use it, but qname_hash needs to be known.
        uint32_t expected_hash = 0;
        calculate_hash_strict_impl(b.buf, sizeof(struct dns_hdr), b.len, &expected_hash);
        struct cache_key key = { .name_hash = expected_hash, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN, ._pad = 0 };
        struct cache_value val;
        int err = bpf_map_lookup_elem(test_ctx.cache_map_fd, &key, &val);
        TEST_ASSERT(err == 0, "test_min_ttl_selection: cache entry found in map");
        if (err == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
            uint64_t ttl_ns = val.expire_ts - now_ns;
            // TTL should be around 120s (allow small timing variance)
            TEST_ASSERT(ttl_ns <= 121ULL * 1000000000ULL && ttl_ns >= 119ULL * 1000000000ULL, "test_min_ttl_selection: min TTL correctly chosen as 120");
        }
    }
}

// 5. test_cache_key_construction
static void test_cache_key_construction() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x9999, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "key.test.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {8, 8, 8, 8};
    builder_add_answer(&b, "key.test.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_cache_key_construction: handle_packet returns 0");
    if (has_bpf) {
        uint32_t expected_hash = 0;
        calculate_hash_strict_impl(b.buf, sizeof(struct dns_hdr), b.len, &expected_hash);
        struct cache_key key = { .name_hash = expected_hash, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN, ._pad = 0 };
        struct cache_value val;
        int err = bpf_map_lookup_elem(test_ctx.cache_map_fd, &key, &val);
        TEST_ASSERT(err == 0, "test_cache_key_construction: exact cache key matched");
    }
}

// 6. test_sequential_stores
static void test_sequential_stores() {
    setup_test();
    
    struct dns_builder b1, b2, b3;
    uint8_t a_rdata[4] = {1, 1, 1, 1};
    
    builder_init(&b1, 1, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b1, "seq1.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b1, "seq1.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);
    
    builder_init(&b2, 2, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b2, "seq2.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b2, "seq2.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    builder_init(&b3, 3, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b3, "seq3.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b3, "seq3.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    int ret1 = call_handle_packet(&test_ctx, b1.buf, b1.len);
    int ret2 = call_handle_packet(&test_ctx, b2.buf, b2.len);
    int ret3 = call_handle_packet(&test_ctx, b3.buf, b3.len);
    TEST_ASSERT(ret1 == 0 && ret2 == 0 && ret3 == 0, "test_sequential_stores: handle_packet returns 0");

    if (has_bpf) {
        TEST_ASSERT(test_next_idx == 3, "test_sequential_stores: next_idx is 3");
        // Verify distinct packets
        TEST_ASSERT(memcmp(test_entries[0].pkt, test_entries[1].pkt, 32) != 0, "test_sequential_stores: entries differ");
    }
}

/* --- Negative Tests --- */

// 7. test_reject_query
static void test_reject_query() {
    setup_test();
    struct dns_builder b;
    // QR=0 (query) -> flags = 0x0100 (standard query)
    builder_init(&b, 0x1234, 0x0100, 1, 0, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_query: next_idx unchanged");
}

// 8. test_reject_truncated
static void test_reject_truncated() {
    setup_test();
    struct dns_builder b;
    // TC=1 -> flags = 0x8380
    builder_init(&b, 0x1234, 0x8380, 1, 1, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_truncated: next_idx unchanged");
}

// 9. test_reject_rcode_nonzero
static void test_reject_rcode_nonzero() {
    setup_test();
    struct dns_builder b;
    // RCODE=3 (NXDOMAIN) -> flags = 0x8183
    builder_init(&b, 0x1234, 0x8183, 1, 0, 0, 0);
    builder_add_question(&b, "nxdomain.example.com", DNS_TYPE_A, DNS_CLASS_IN);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_rcode_nonzero: next_idx unchanged");
}

// 10. test_reject_ancount_zero
static void test_reject_ancount_zero() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 0, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_ancount_zero: next_idx unchanged");
}

// 11. test_reject_qdcount_not_one
static void test_reject_qdcount_not_one() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 2, 1, 0, 0);
    builder_add_question(&b, "one.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_question(&b, "two.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "one.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_qdcount_not_one: next_idx unchanged");
}

// 12. test_reject_too_short
static void test_reject_too_short() {
    setup_test();
    uint8_t short_pkt[4] = {0, 1, 2, 3}; // < 12 bytes
    call_handle_packet(&test_ctx, short_pkt, sizeof(short_pkt));
    TEST_ASSERT(test_next_idx == 0, "test_reject_too_short: next_idx unchanged");
}

// 13. test_reject_ttl_zero
static void test_reject_ttl_zero() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN, 0, 4, a_rdata); // TTL = 0

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_ttl_zero: next_idx unchanged");
}

// 14. test_reject_unsupported_rtype
static void test_reject_unsupported_rtype() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t cname_rdata[10] = {3, 'b', 'a', 'd', 3, 'c', 'o', 'm', 0}; 
    // RTYPE = 5 (CNAME)
    builder_add_answer(&b, "www.example.com", 5, DNS_CLASS_IN, 300, 9, cname_rdata);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 0, "test_reject_unsupported_rtype: next_idx unchanged");
}

/* --- Edge Cases --- */

// 15. test_oversized_packet
static void test_oversized_packet() {
    setup_test();
    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "huge.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    
    // We add a giant RDATA to make it exceed 512 bytes flat_len
    uint8_t big_rdata[600];
    memset(big_rdata, 1, sizeof(big_rdata));
    // RTYPE 1 (A), but 600 bytes is physically invalid for A. 
    // The parser accepts it as long as type is A/AAAA and it fits in flat_len.
    // If it exceeds flat_len, it should fail.
    builder_add_answer(&b, "huge.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 600, big_rdata);

    call_handle_packet(&test_ctx, b.buf, b.len);
    // next_idx might not change if store_to_cache fails on flat_len > 512
    // Or if handle_packet fails earlier
    TEST_ASSERT(test_next_idx == 0, "test_oversized_packet: next_idx unchanged");
}

// 16. test_arena_full
static void test_arena_full() {
    setup_test();
    test_ctx.max_entries = 1;
    test_next_idx = 1; // already full

    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "full.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "full.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(test_next_idx == 1, "test_arena_full: next_idx unchanged");
}

// 17. test_null_ctx
static void test_null_ctx() {
    setup_test();
    test_ctx.entries = NULL;

    struct dns_builder b;
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "null.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    uint8_t a_rdata[4] = {1, 2, 3, 4};
    builder_add_answer(&b, "null.example.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, a_rdata);

    int ret = call_handle_packet(&test_ctx, b.buf, b.len);
    TEST_ASSERT(ret == 0, "test_null_ctx: no crash, returns 0");
    TEST_ASSERT(test_next_idx == 0, "test_null_ctx: next_idx unchanged");
}


int main(void) {
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "test_cache", sizeof(struct cache_key), sizeof(struct cache_value), 64, &opts);
    if (map_fd >= 0) {
        has_bpf = 1;
        test_ctx.cache_map_fd = map_fd;
        printf("BPF map created successfully (fd=%d)\n", map_fd);
    } else {
        has_bpf = 0;
        test_ctx.cache_map_fd = -1;
        printf("[WARN] BPF map creation failed (need root?), cache store tests will be skipped\n");
    }

    printf("\n--- Running DNS Parser Tests ---\n");
    
    test_simple_a_record();
    test_simple_aaaa_record();
    test_multiple_a_records();
    test_min_ttl_selection();
    test_cache_key_construction();
    test_sequential_stores();

    test_reject_query();
    test_reject_truncated();
    test_reject_rcode_nonzero();
    test_reject_ancount_zero();
    test_reject_qdcount_not_one();
    test_reject_too_short();
    test_reject_ttl_zero();
    test_reject_unsupported_rtype();

    test_oversized_packet();
    test_arena_full();
    test_null_ctx();

    if (map_fd >= 0) {
        close(map_fd);
    }

    printf("\nTotal: %d, Passed: %d, Failed: %d\n", test_count, pass_count, test_count - pass_count);
    return (pass_count == test_count) ? 0 : 1;
}
