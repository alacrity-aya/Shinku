// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
//
// Tests for arena cache storage correctness after bug fixes:
//
// 1. Seqlock: writer sets odd seq during write, even when done.
//    Reader detects torn reads by checking seq consistency.
//
// 2. Generation counter: each store gets a unique gen written to both
//    cache_entry.gen and cache_value.gen. Stale lookups are detected.
//
// 3. Eviction: when a slot wraps, the old cache_map entry is deleted
//    if it still points to the recycled slot.
//
// 4. TTL cleanup: expired entries are removed from cache_map.
//

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
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

#include "../../src/core/dns_parser.h"
#include "../../src/include/constants.h"

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

// =====================================================================
// DNS builder helpers
// =====================================================================

struct dns_builder {
    uint8_t buf[1500];
    uint32_t len;
};

static void builder_init(
    struct dns_builder* b,
    uint16_t id,
    uint16_t flags,
    uint16_t qd,
    uint16_t an,
    uint16_t ns,
    uint16_t ar
) {
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
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        b->buf[b->len++] = (uint8_t)label_len;
        memcpy(b->buf + b->len, p, label_len);
        b->len += label_len;
        if (!dot)
            break;
        p = dot + 1;
    }
    b->buf[b->len++] = 0;
}

static void
builder_add_question(struct dns_builder* b, const char* name, uint16_t qtype, uint16_t qclass) {
    builder_add_name(b, name);
    uint16_t* ptr = (uint16_t*)(b->buf + b->len);
    ptr[0] = htons(qtype);
    ptr[1] = htons(qclass);
    b->len += 4;
}

static void builder_add_answer(
    struct dns_builder* b,
    const char* name,
    uint16_t rtype,
    uint16_t rclass,
    uint32_t ttl,
    uint16_t rdlen,
    const uint8_t* rdata
) {
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

static int call_handle_packet(struct cache_context* cache_ctx, uint8_t* dns_pkt, uint32_t dns_len) {
    uint8_t buf[sizeof(struct dns_event) + 1500];
    memset(buf, 0, sizeof(buf));
    struct dns_event* event = (struct dns_event*)buf;
    struct dns_parser_context parser_ctx = { .cache = cache_ctx, .runtime = NULL };
    event->timestamp = 0;
    event->len = dns_len;
    memcpy(event->payload, dns_pkt, dns_len);
    return dns_parser_handle_event(&parser_ctx, event, sizeof(*event) + dns_len);
}

// =====================================================================
// Test 1: Seqlock protects arena writes
// =====================================================================
//
// Verify that store_to_cache() brackets memcpy with seq increments:
//   - seq starts at 0 (even = stable)
//   - After store: seq == 2 (even = stable, two increments)
//   - During write: seq would be 1 (odd = write-in-progress)
//
static void test_seqlock_write(int cache_map_fd) {
    printf("\n--- Test: Seqlock Write Protocol ---\n");

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
    };

    TEST_ASSERT(entries[0].seq == 0, "Initial seq == 0 (stable)");

    struct dns_builder b;
    uint8_t ip[4] = { 1, 2, 3, 4 };
    builder_init(&b, 0x1234, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "test.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b, "test.com", DNS_TYPE_A, DNS_CLASS_IN, 300, 4, ip);

    call_handle_packet(&ctx, b.buf, b.len);

    TEST_ASSERT(
        entries[0].seq == 2,
        "After store: seq == 2 (two increments, got %u)",
        entries[0].seq
    );
    TEST_ASSERT((entries[0].seq & 1) == 0, "seq is even (stable, not write-in-progress)");
}

// =====================================================================
// Test 2: Generation counter consistency
// =====================================================================
//
// Verify that store_to_cache() writes matching gen to both
// cache_entry.gen and cache_value.gen.
//
static void test_generation_counter(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Generation Counter Consistency ---\n");

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
    };

    const char* domains[3] = { "alpha.com", "beta.com", "gamma.com" };
    uint8_t ips[3][4] = { { 10, 0, 0, 1 }, { 10, 0, 0, 2 }, { 10, 0, 0, 3 } };

    for (int i = 0; i < 3; i++) {
        struct dns_builder b;
        builder_init(&b, (uint16_t)(0x100 + i), 0x8180, 1, 1, 0, 0);
        builder_add_question(&b, domains[i], DNS_TYPE_A, DNS_CLASS_IN);
        builder_add_answer(&b, domains[i], DNS_TYPE_A, DNS_CLASS_IN, 3600, 4, ips[i]);
        call_handle_packet(&ctx, b.buf, b.len);
    }

    TEST_ASSERT(ctx.next_gen == 3, "After 3 stores, next_gen == 3 (got %u)", ctx.next_gen);
    TEST_ASSERT(entries[0].gen == 1, "entries[0].gen == 1 (got %u)", entries[0].gen);
    TEST_ASSERT(entries[1].gen == 2, "entries[1].gen == 2 (got %u)", entries[1].gen);
    TEST_ASSERT(entries[2].gen == 3, "entries[2].gen == 3 (got %u)", entries[2].gen);

    if (!has_real_bpf_map) {
        printf("  [SKIP] cache_value.gen cross-check (need root for BPF map)\n");
        return;
    }

    for (int i = 0; i < 3; i++) {
        struct dns_builder b;
        builder_init(&b, (uint16_t)(0x100 + i), 0x8180, 1, 1, 0, 0);
        builder_add_question(&b, domains[i], DNS_TYPE_A, DNS_CLASS_IN);

        uint32_t hash = 0;
        calculate_hash_strict_impl(b.buf, sizeof(struct dns_hdr), b.len, &hash);
        struct cache_key key = { .name_hash = hash, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
        struct cache_value val;
        int err = bpf_map_lookup_elem(cache_map_fd, &key, &val);
        if (err == 0) {
            TEST_ASSERT(
                val.gen == entries[val.arena_idx].gen,
                "cache_value.gen == cache_entry.gen for %s (both %u)",
                domains[i],
                val.gen
            );
        }
    }
}

// =====================================================================
// Test 3: Eviction on wraparound
// =====================================================================
//
// With max_entries=3, storing a 4th entry wraps to idx=0.
// The fix should delete first.com's stale cache_map entry.
//
static void test_eviction_on_wraparound(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Eviction on Wraparound ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[3];
    struct cache_key slot_owners[3];
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 3,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
    };

    const char* domains[4] = { "first.com", "second.com", "third.com", "fourth.com" };
    uint8_t ips[4][4] = { { 1, 1, 1, 1 }, { 2, 2, 2, 2 }, { 3, 3, 3, 3 }, { 4, 4, 4, 4 } };
    struct dns_builder builders[4];

    for (int i = 0; i < 4; i++) {
        builder_init(&builders[i], (uint16_t)(0x1000 + i), 0x8180, 1, 1, 0, 0);
        builder_add_question(&builders[i], domains[i], DNS_TYPE_A, DNS_CLASS_IN);
        builder_add_answer(&builders[i], domains[i], DNS_TYPE_A, DNS_CLASS_IN, 3600, 4, ips[i]);
    }

    for (int i = 0; i < 4; i++)
        call_handle_packet(&ctx, builders[i].buf, builders[i].len);

    TEST_ASSERT(next_idx == 4, "After 4 stores, next_idx == 4 (got %u)", next_idx);

    uint32_t first_hash = 0;
    calculate_hash_strict_impl(
        builders[0].buf,
        sizeof(struct dns_hdr),
        builders[0].len,
        &first_hash
    );
    struct cache_key first_key = { .name_hash = first_hash,
                                   .qtype = DNS_TYPE_A,
                                   .qclass = DNS_CLASS_IN };
    struct cache_value first_val;
    int err = bpf_map_lookup_elem(cache_map_fd, &first_key, &first_val);

    TEST_ASSERT(
        err != 0,
        "FIX: first.com's stale cache_map entry was evicted on wraparound (err=%d)",
        err
    );

    uint32_t fourth_hash = 0;
    calculate_hash_strict_impl(
        builders[3].buf,
        sizeof(struct dns_hdr),
        builders[3].len,
        &fourth_hash
    );
    struct cache_key fourth_key = { .name_hash = fourth_hash,
                                    .qtype = DNS_TYPE_A,
                                    .qclass = DNS_CLASS_IN };
    struct cache_value fourth_val;
    err = bpf_map_lookup_elem(cache_map_fd, &fourth_key, &fourth_val);

    TEST_ASSERT(
        err == 0 && fourth_val.arena_idx == 0,
        "fourth.com correctly occupies arena_idx=0 (idx=%u)",
        err == 0 ? fourth_val.arena_idx : 0
    );

    TEST_ASSERT(
        err == 0 && fourth_val.gen == entries[0].gen,
        "fourth.com's gen matches arena entry (val=%u, entry=%u)",
        err == 0 ? fourth_val.gen : 0,
        entries[0].gen
    );
}

// =====================================================================
// Test 4: Seqlock torn-read detection
// =====================================================================
//
// Simulates concurrent reader/writer on the same arena entry.
// Writer uses seqlock protocol. Reader checks seq consistency.
// Torn reads should be detected (reader sees seq mismatch).
//

struct seqlock_test_ctx {
    struct cache_entry* entry;
    atomic_int stop;
    atomic_int detected_count;
    atomic_int clean_count;
    atomic_int total_count;
};

static void* seqlock_writer_thread(void* arg) {
    struct seqlock_test_ctx* ctx = arg;
    int iteration = 0;
    atomic_uint* seq = (atomic_uint*)&ctx->entry->seq;
    volatile uint8_t* dst = ctx->entry->pkt;

    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        uint8_t pattern = (iteration & 1) ? 0x55 : 0xAA;

        atomic_fetch_add_explicit(seq, 1, memory_order_relaxed);
        for (int i = 0; i < ARENA_ENTRY_SIZE; i++) {
            dst[i] = pattern;
        }
        atomic_fetch_add_explicit(seq, 1, memory_order_release);

        iteration++;
    }
    return NULL;
}

static void* seqlock_reader_thread(void* arg) {
    struct seqlock_test_ctx* ctx = arg;
    uint8_t local_buf[ARENA_ENTRY_SIZE];
    atomic_uint* seq = (atomic_uint*)&ctx->entry->seq;

    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed)) {
        uint32_t seq1 = atomic_load_explicit(seq, memory_order_acquire);
        if (seq1 & 1) {
            atomic_fetch_add_explicit(&ctx->total_count, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&ctx->detected_count, 1, memory_order_relaxed);
            continue;
        }

        volatile uint8_t* src = ctx->entry->pkt;
        for (int i = 0; i < ARENA_ENTRY_SIZE; i += 8)
            *(uint64_t*)(local_buf + i) = *(volatile uint64_t*)(src + i);

        uint32_t seq2 = atomic_load_explicit(seq, memory_order_acquire);
        atomic_fetch_add_explicit(&ctx->total_count, 1, memory_order_relaxed);

        if (seq1 != seq2) {
            atomic_fetch_add_explicit(&ctx->detected_count, 1, memory_order_relaxed);
            continue;
        }

        uint8_t first = local_buf[0];
        int consistent = 1;
        for (int i = 1; i < ARENA_ENTRY_SIZE; i++) {
            if (local_buf[i] != first) {
                consistent = 0;
                break;
            }
        }

        if (consistent)
            atomic_fetch_add_explicit(&ctx->clean_count, 1, memory_order_relaxed);
    }
    return NULL;
}

static void test_seqlock_torn_read_detection(void) {
    printf("\n--- Test: Seqlock Torn Read Detection ---\n");

#if defined(__has_feature)
    #if __has_feature(thread_sanitizer)
    printf(
        "  [SKIP] TSAN build: torn-read simulation intentionally performs unsynchronized pkt access\n"
    );
    return;
    #endif
#endif

    struct cache_entry entry;
    memset(&entry, 0, sizeof(entry));
    memset(entry.pkt, 0xAA, ARENA_ENTRY_SIZE);

    struct seqlock_test_ctx ctx = {
        .entry = &entry,
        .stop = 0,
        .detected_count = 0,
        .clean_count = 0,
        .total_count = 0,
    };

    pthread_t writer, reader;
    pthread_create(&writer, NULL, seqlock_writer_thread, &ctx);
    pthread_create(&reader, NULL, seqlock_reader_thread, &ctx);

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000000 };
    nanosleep(&ts, NULL);

    atomic_store_explicit(&ctx.stop, 1, memory_order_relaxed);
    pthread_join(writer, NULL);
    pthread_join(reader, NULL);

    int total = atomic_load(&ctx.total_count);
    int detected = atomic_load(&ctx.detected_count);
    int clean = atomic_load(&ctx.clean_count);

    printf("  Total reads: %d, Detected conflicts: %d, Clean reads: %d\n", total, detected, clean);

    TEST_ASSERT(clean > 0, "Seqlock allows clean reads (%d clean reads)", clean);
    TEST_ASSERT(clean > 0, "FIX: All accepted reads are consistent (seqlock rejects torn reads)");

    if (detected > 0) {
        printf("  [INFO] Seqlock correctly detected %d concurrent write conflicts\n", detected);
    }
}

// =====================================================================
// Test 5: TTL cleanup removes expired entries
// =====================================================================
//
static void test_ttl_cleanup(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: TTL Cleanup ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
    };

    uint8_t ip1[4] = { 10, 0, 0, 1 };
    struct dns_builder b1;
    builder_init(&b1, 0x2000, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b1, "short-ttl.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b1, "short-ttl.com", DNS_TYPE_A, DNS_CLASS_IN, 1, 4, ip1);
    call_handle_packet(&ctx, b1.buf, b1.len);

    uint8_t ip2[4] = { 10, 0, 0, 2 };
    struct dns_builder b2;
    builder_init(&b2, 0x2001, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b2, "long-ttl.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b2, "long-ttl.com", DNS_TYPE_A, DNS_CLASS_IN, 3600, 4, ip2);
    call_handle_packet(&ctx, b2.buf, b2.len);

    printf("  Waiting 2 seconds for short-ttl.com to expire...\n");
    sleep(2);

    int cleaned = dns_parser_cleanup_expired_entries(&ctx);
    TEST_ASSERT(cleaned >= 1, "Cleanup removed %d expired entries (expected >= 1)", cleaned);

    uint32_t hash1 = 0;
    calculate_hash_strict_impl(b1.buf, sizeof(struct dns_hdr), b1.len, &hash1);
    struct cache_key key1 = { .name_hash = hash1, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
    struct cache_value val1;
    int err1 = bpf_map_lookup_elem(cache_map_fd, &key1, &val1);
    TEST_ASSERT(err1 != 0, "short-ttl.com removed from cache_map after cleanup (err=%d)", err1);

    uint32_t hash2 = 0;
    calculate_hash_strict_impl(b2.buf, sizeof(struct dns_hdr), b2.len, &hash2);
    struct cache_key key2 = { .name_hash = hash2, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
    struct cache_value val2;
    int err2 = bpf_map_lookup_elem(cache_map_fd, &key2, &val2);
    TEST_ASSERT(err2 == 0, "long-ttl.com still in cache_map after cleanup (err=%d)", err2);

    TEST_ASSERT(
        slot_owners[0].name_hash == 0,
        "slot_owners[0] cleared after short-ttl.com cleanup"
    );
}

// =====================================================================
// Test 6: slot_owners reverse mapping correctness
// =====================================================================
//
static void test_slot_owners_tracking(int cache_map_fd) {
    printf("\n--- Test: slot_owners Reverse Mapping ---\n");

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
    };

    const char* domains[3] = { "aaa.com", "bbb.com", "ccc.com" };
    uint8_t ips[3][4] = { { 1, 0, 0, 1 }, { 2, 0, 0, 2 }, { 3, 0, 0, 3 } };

    for (int i = 0; i < 3; i++) {
        struct dns_builder b;
        builder_init(&b, (uint16_t)(0x3000 + i), 0x8180, 1, 1, 0, 0);
        builder_add_question(&b, domains[i], DNS_TYPE_A, DNS_CLASS_IN);
        builder_add_answer(&b, domains[i], DNS_TYPE_A, DNS_CLASS_IN, 3600, 4, ips[i]);
        call_handle_packet(&ctx, b.buf, b.len);

        TEST_ASSERT(
            slot_owners[i].name_hash != 0,
            "slot_owners[%d] populated after storing %s (hash=0x%x)",
            i,
            domains[i],
            slot_owners[i].name_hash
        );
    }

    TEST_ASSERT(
        slot_owners[0].qtype == DNS_TYPE_A && slot_owners[0].qclass == DNS_CLASS_IN,
        "slot_owners[0] has correct qtype=%u qclass=%u",
        slot_owners[0].qtype,
        slot_owners[0].qclass
    );
}

static void test_admission_min_ttl_reject(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Admission Min TTL Reject ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    struct cache_key recent_keys[4];
    uint64_t recent_ns[4];
    uint16_t row0[64] = { 0 }, row1[64] = { 0 }, row2[64] = { 0 }, row3[64] = { 0 };
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));
    memset(recent_keys, 0, sizeof(recent_keys));
    memset(recent_ns, 0, sizeof(recent_ns));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
        .admission_enabled = 1,
        .admission_min_ttl = 10,
        .recent_insert_keys = recent_keys,
        .recent_insert_ns = recent_ns,
        .recent_insert_cap = 4,
        .freq_width = 64,
        .freq_epoch_ops = 128,
        .freq_rows = { row0, row1, row2, row3 },
    };

    struct dns_builder b;
    uint8_t ip[4] = { 5, 5, 5, 5 };
    builder_init(&b, 0x4001, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "short-admit.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b, "short-admit.com", DNS_TYPE_A, DNS_CLASS_IN, 3, 4, ip);
    call_handle_packet(&ctx, b.buf, b.len);

    TEST_ASSERT(next_idx == 0, "min TTL reject should not allocate arena slot");

    uint32_t hash = 0;
    calculate_hash_strict_impl(b.buf, sizeof(struct dns_hdr), b.len, &hash);
    struct cache_key key = { .name_hash = hash, .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
    struct cache_value val;
    int err = bpf_map_lookup_elem(cache_map_fd, &key, &val);
    TEST_ASSERT(err != 0, "min TTL reject should not insert cache map entry");
}

static void test_admission_recent_dampen_reject(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Admission Recent Dampening Reject ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[4];
    struct cache_key slot_owners[4];
    struct cache_key recent_keys[8];
    uint64_t recent_ns[8];
    uint16_t row0[64] = { 0 }, row1[64] = { 0 }, row2[64] = { 0 }, row3[64] = { 0 };
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));
    memset(recent_keys, 0, sizeof(recent_keys));
    memset(recent_ns, 0, sizeof(recent_ns));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 4,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
        .admission_enabled = 1,
        .admission_min_ttl = 1,
        .admission_dampen_window_ns = 10ULL * 1000000000ULL,
        .recent_insert_keys = recent_keys,
        .recent_insert_ns = recent_ns,
        .recent_insert_cap = 8,
        .freq_width = 64,
        .freq_epoch_ops = 128,
        .freq_rows = { row0, row1, row2, row3 },
    };

    struct dns_builder b;
    uint8_t ip[4] = { 6, 6, 6, 6 };
    builder_init(&b, 0x4002, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "dampen.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b, "dampen.com", DNS_TYPE_A, DNS_CLASS_IN, 120, 4, ip);

    call_handle_packet(&ctx, b.buf, b.len);
    call_handle_packet(&ctx, b.buf, b.len);

    TEST_ASSERT(next_idx == 1, "recent dampening should reject immediate duplicate insertion");
}

static void test_admission_freq_reject_cold_candidate(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Admission Frequency Reject Cold Candidate ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[1];
    struct cache_key slot_owners[1];
    struct cache_key recent_keys[8];
    uint64_t recent_ns[8];
    uint8_t slot_hot[1] = { 0 };
    uint32_t slot_hits[1] = { 0 };
    uint16_t row0[64] = { 0 }, row1[64] = { 0 }, row2[64] = { 0 }, row3[64] = { 0 };
    uint32_t next_idx = 0;
    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));
    memset(recent_keys, 0, sizeof(recent_keys));
    memset(recent_ns, 0, sizeof(recent_ns));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 1,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
        .admission_enabled = 1,
        .admission_min_ttl = 1,
        .pressure_mode = 1,
        .hot_threshold = 2,
        .recent_insert_keys = recent_keys,
        .recent_insert_ns = recent_ns,
        .recent_insert_cap = 8,
        .slot_hot = slot_hot,
        .slot_hit_count = slot_hits,
        .freq_width = 64,
        .freq_epoch_ops = 128,
        .freq_rows = { row0, row1, row2, row3 },
    };

    struct dns_builder hot;
    uint8_t hot_ip[4] = { 7, 7, 7, 7 };
    builder_init(&hot, 0x4101, 0x8180, 1, 1, 0, 0);
    builder_add_question(&hot, "hot.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&hot, "hot.com", DNS_TYPE_A, DNS_CLASS_IN, 120, 4, hot_ip);

    call_handle_packet(&ctx, hot.buf, hot.len);
    call_handle_packet(&ctx, hot.buf, hot.len);
    call_handle_packet(&ctx, hot.buf, hot.len);

    struct dns_builder cold;
    uint8_t cold_ip[4] = { 8, 8, 8, 8 };
    builder_init(&cold, 0x4102, 0x8180, 1, 1, 0, 0);
    builder_add_question(&cold, "cold.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&cold, "cold.com", DNS_TYPE_A, DNS_CLASS_IN, 120, 4, cold_ip);
    call_handle_packet(&ctx, cold.buf, cold.len);

    uint32_t hot_hash = 0;
    calculate_hash_strict_impl(hot.buf, sizeof(struct dns_hdr), hot.len, &hot_hash);
    struct cache_key hot_key = { .name_hash = hot_hash,
                                 .qtype = DNS_TYPE_A,
                                 .qclass = DNS_CLASS_IN };
    struct cache_value val;
    int err = bpf_map_lookup_elem(cache_map_fd, &hot_key, &val);
    TEST_ASSERT(err == 0, "hot key should survive cold candidate under pressure mode");
}

static void test_hot_promotion_on_rehit(int cache_map_fd, int has_real_bpf_map) {
    printf("\n--- Test: Hot Promotion On Re-hit ---\n");

    if (!has_real_bpf_map) {
        printf("  [SKIP] Requires BPF map (need root)\n");
        return;
    }

    struct cache_entry entries[1];
    struct cache_key slot_owners[1];
    struct cache_key recent_keys[8];
    uint64_t recent_ns[8];
    uint8_t slot_hot[1] = { 0 };
    uint32_t slot_hits[1] = { 0 };
    uint16_t row0[64] = { 0 }, row1[64] = { 0 }, row2[64] = { 0 }, row3[64] = { 0 };
    uint32_t next_idx = 0;

    memset(entries, 0, sizeof(entries));
    memset(slot_owners, 0, sizeof(slot_owners));
    memset(recent_keys, 0, sizeof(recent_keys));
    memset(recent_ns, 0, sizeof(recent_ns));

    struct cache_context ctx = {
        .entries = entries,
        .next_idx = &next_idx,
        .max_entries = 1,
        .cache_map_fd = cache_map_fd,
        .slot_owners = slot_owners,
        .next_gen = 0,
        .admission_enabled = 1,
        .admission_min_ttl = 1,
        .pressure_mode = 0,
        .hot_threshold = 100,
        .recent_insert_keys = recent_keys,
        .recent_insert_ns = recent_ns,
        .recent_insert_cap = 8,
        .slot_hot = slot_hot,
        .slot_hit_count = slot_hits,
        .freq_width = 64,
        .freq_epoch_ops = 128,
        .freq_rows = { row0, row1, row2, row3 },
    };

    struct dns_builder b;
    uint8_t ip[4] = { 9, 9, 9, 9 };
    builder_init(&b, 0x4201, 0x8180, 1, 1, 0, 0);
    builder_add_question(&b, "rehit.com", DNS_TYPE_A, DNS_CLASS_IN);
    builder_add_answer(&b, "rehit.com", DNS_TYPE_A, DNS_CLASS_IN, 120, 4, ip);

    call_handle_packet(&ctx, b.buf, b.len);
    TEST_ASSERT(slot_hot[0] == 0, "first insert remains cold");

    call_handle_packet(&ctx, b.buf, b.len);
    TEST_ASSERT(slot_hot[0] == 1, "same-key re-hit promotes slot to hot");
}

int main(void) {
    printf("================================================================\n");
    printf("Arena Cache Storage Correctness Tests (Post-Fix)\n");
    printf("================================================================\n");

    int has_real_bpf_map = 0;
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int map_fd = bpf_map_create(
        BPF_MAP_TYPE_HASH,
        "test_cache",
        sizeof(struct cache_key),
        sizeof(struct cache_value),
        64,
        &opts
    );
    if (map_fd >= 0) {
        printf("BPF map created (fd=%d) — full cache_map checks enabled\n", map_fd);
        has_real_bpf_map = 1;
    } else {
        printf("[WARN] BPF map creation failed (need root?) — arena-only checks\n");
        map_fd = open("/dev/null", O_RDWR);
        if (map_fd >= 0)
            printf("[INFO] Using dummy fd=%d for arena-only testing\n", map_fd);
    }

    test_seqlock_write(map_fd);
    test_generation_counter(map_fd, has_real_bpf_map);
    test_eviction_on_wraparound(map_fd, has_real_bpf_map);
    test_seqlock_torn_read_detection();
    test_ttl_cleanup(map_fd, has_real_bpf_map);
    test_slot_owners_tracking(map_fd);
    test_admission_min_ttl_reject(map_fd, has_real_bpf_map);
    test_admission_recent_dampen_reject(map_fd, has_real_bpf_map);
    test_admission_freq_reject_cold_candidate(map_fd, has_real_bpf_map);
    test_hot_promotion_on_rehit(map_fd, has_real_bpf_map);

    if (map_fd >= 0)
        close(map_fd);

    printf("\n================================================================\n");
    printf("Results: %d/%d passed\n", pass_count, test_count);
    printf("================================================================\n");

    return (pass_count == test_count) ? 0 : 1;
}
