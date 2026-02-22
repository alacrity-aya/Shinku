// Tests for DNS name hashing and flattening functions
// This test suite validates the correctness of DNS name hashing and flattening functions in both XDP and user space contexts.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define __BPF__ as false to enable test functions
#ifndef __BPF__
    #define __BPF__ 0
#endif

// Type definitions (mimic BPF types for userspace testing)
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#ifndef __always_inline
    #define __always_inline inline
#endif

// Include source files to access testable functions
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

// Function declarations for the functions we'll test
int calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out);
int calculate_hash_strict_impl(const __u8* packet, int offset, int max_len, uint32_t* out_hash);
int flatten_name_impl(const __u8* packet, int offset, int max_len, __u8* dest, int dest_max);

// For compatibility, define the function used in tests
static int calculate_dns_name_hash_xdp(void** cursor, void* data_end, __u32* hash_out) {
    return calculate_dns_name_hash_test(cursor, data_end, hash_out);
}

// =============================================================================
// Test Cases
// =============================================================================

static void test_xdp_basic_names(void) {
    printf("\n[TEST] XDP Hash - Basic Names (No Compression)\n");

    // Test: www.example.com
    __u8 pkt1[] = { 0x03, 'w', 'w', 'w',  0x07, 'e', 'x', 'a', 'm',
                    'p',  'l', 'e', 0x03, 'c',  'o', 'm', 0x00 };
    void* cursor = pkt1;
    __u32 hash = 0;
    int ret = calculate_dns_name_hash_xdp(&cursor, pkt1 + sizeof(pkt1), &hash);
    TEST_ASSERT(ret == 0, "www.example.com: return=0");
    TEST_ASSERT(hash == 0x0E191BCA, "www.example.com: hash=0x%08X", hash);

    // Test: google.com
    __u8 pkt2[] = { 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    cursor = pkt2;
    hash = 0;
    ret = calculate_dns_name_hash_xdp(&cursor, pkt2 + sizeof(pkt2), &hash);
    TEST_ASSERT(ret == 0, "google.com: return=0");
    TEST_ASSERT(hash != 0, "google.com: hash=0x%08X", hash);

    // Test: Root domain
    __u8 pkt3[] = { 0x00 };
    cursor = pkt3;
    hash = 0;
    ret = calculate_dns_name_hash_xdp(&cursor, pkt3 + sizeof(pkt3), &hash);
    TEST_ASSERT(ret == 0, "root domain: return=0");
    TEST_ASSERT(hash == FNV_OFFSET_BASIS_32, "root domain: hash=FNV_OFFSET_BASIS_32");
}

static void test_xdp_compression_rejected(void) {
    printf("\n[TEST] XDP Hash - Compression Pointer Rejection\n");

    // Packet with compression pointer (should fail)
    __u8 pkt[] = { 0x03, 'w', 'w', 'w', 0xC0, 0x00 }; // www + pointer to offset 0
    void* cursor = pkt;
    __u32 hash = 0;
    int ret = calculate_dns_name_hash_xdp(&cursor, pkt + sizeof(pkt), &hash);
    TEST_ASSERT(ret == -1, "compression pointer rejected: return=-1");
}

static void test_xdp_case_normalization(void) {
    printf("\n[TEST] XDP Hash - Case Normalization\n");

    // WWW.EXAMPLE.COM (uppercase)
    __u8 pkt_upper[] = { 0x03, 'W', 'W', 'W',  0x07, 'E', 'X', 'A', 'M',
                         'P',  'L', 'E', 0x03, 'C',  'O', 'M', 0x00 };
    // www.example.com (lowercase)
    __u8 pkt_lower[] = { 0x03, 'w', 'w', 'w',  0x07, 'e', 'x', 'a', 'm',
                         'p',  'l', 'e', 0x03, 'c',  'o', 'm', 0x00 };

    void* cursor = pkt_upper;
    __u32 hash_upper = 0;
    calculate_dns_name_hash_xdp(&cursor, pkt_upper + sizeof(pkt_upper), &hash_upper);

    cursor = pkt_lower;
    __u32 hash_lower = 0;
    calculate_dns_name_hash_xdp(&cursor, pkt_lower + sizeof(pkt_lower), &hash_lower);

    TEST_ASSERT(
        hash_upper == hash_lower,
        "case insensitive: upper=0x%08X == lower=0x%08X",
        hash_upper,
        hash_lower
    );
}

static void test_xdp_bounds_check(void) {
    printf("\n[TEST] XDP Hash - Bounds Checking\n");

    // Truncated packet (label says 5 bytes but only 2 available)
    __u8 pkt_truncated[] = { 0x05, 'a', 'b' }; // says 5 bytes, only 2 provided
    void* cursor = pkt_truncated;
    __u32 hash = 0;
    int ret = calculate_dns_name_hash_xdp(&cursor, pkt_truncated + sizeof(pkt_truncated), &hash);
    TEST_ASSERT(ret == -1, "truncated packet rejected: return=-1");
}

static void test_user_space_compression(void) {
    printf("\n[TEST] User Space Hash - Compression Pointer Support\n");

    // Build packet: google.com at offset 10, mail.google.com uses compression
    __u8 pkt[100] = { 0 };
    // google.com at offset 10: \x06google\x03com\x00
    __u8 google_com[] = { 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    memcpy(&pkt[10], google_com, sizeof(google_com));

    // mail.google.com at offset 30 with compression pointer
    pkt[30] = 0x04; // length of "mail"
    memcpy(&pkt[31], "mail", 4);
    pkt[35] = 0xC0; // compression pointer high byte
    pkt[36] = 0x0A; // compression pointer low byte (offset 10)

    // Test from offset 30 (mail.google.com)
    uint32_t hash = 0;
    int consumed = calculate_hash_strict_impl(pkt, 30, sizeof(pkt), &hash);
    TEST_ASSERT(consumed > 0, "compressed name consumed=%d bytes", consumed);
    TEST_ASSERT(hash != 0, "compressed name hash=0x%08X", hash);

    // Compare with flattened version: mail.google.com
    __u8 flat[] = { 0x04, 'm', 'a', 'i',  'l', 0x06, 'g', 'o', 'o',
                    'g',  'l', 'e', 0x03, 'c', 'o',  'm', 0x00 };
    uint32_t hash_flat = 0;
    calculate_hash_strict_impl(flat, 0, sizeof(flat), &hash_flat);
    TEST_ASSERT(hash == hash_flat, "compressed vs flat hash match: 0x%08X", hash);
}

static void test_flatten_name(void) {
    printf("\n[TEST] Flatten Name - Decompression\n");

    // Build compressed packet
    __u8 pkt[100] = { 0 };
    // google.com at offset 10
    __u8 google_com[] = { 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
    memcpy(&pkt[10], google_com, sizeof(google_com));

    // mail.google.com at offset 30 with compression
    pkt[30] = 0x04;
    memcpy(&pkt[31], "mail", 4);
    pkt[35] = 0xC0;
    pkt[36] = 0x0A; // pointer to offset 10

    __u8 dest[50] = { 0 };
    int len = flatten_name_impl(pkt, 30, sizeof(pkt), dest, sizeof(dest));

    TEST_ASSERT(len > 0, "flatten succeeded: len=%d", len);

    if (len > 0) {
        // Expected: mail.google.com
        __u8 expected[] = { 0x04, 'm', 'a', 'i',  'l', 0x06, 'g', 'o', 'o',
                            'g',  'l', 'e', 0x03, 'c', 'o',  'm', 0x00 };
        TEST_ASSERT(
            len == (int)sizeof(expected),
            "flattened length correct: %d (expected %zu)",
            len,
            sizeof(expected)
        );
        TEST_ASSERT(memcmp(dest, expected, len) == 0, "flattened content correct");
    }
}

static void test_consistency_xdp_vs_user(void) {
    printf("\n[TEST] Consistency - XDP vs User Space (Flat Packets)\n");

    // Define test packets with explicit lengths
    struct {
        const char* name;
        __u8 data[30];
        size_t len;
    } test_cases[] = {
        { "www.example.com",
          { 0x03,
            'w',
            'w',
            'w',
            0x07,
            'e',
            'x',
            'a',
            'm',
            'p',
            'l',
            'e',
            0x03,
            'c',
            'o',
            'm',
            0x00 },
          17 },
        { "google.com", { 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 }, 12 },
        { "example", { 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00 }, 9 },
        { "a.b.c", { 0x01, 'a', 0x01, 'b', 0x01, 'c', 0x00 }, 7 },
    };

    for (int i = 0; i < 4; i++) {
        // XDP hash
        void* cursor = (void*)test_cases[i].data;
        __u32 hash_xdp = 0;
        int ret_xdp =
            calculate_dns_name_hash_xdp(&cursor, test_cases[i].data + test_cases[i].len, &hash_xdp);

        // User space hash
        uint32_t hash_user = 0;
        int ret_user =
            calculate_hash_strict_impl(test_cases[i].data, 0, test_cases[i].len, &hash_user);

        TEST_ASSERT(ret_xdp == 0 && ret_user > 0, "%s: both succeeded", test_cases[i].name);
        TEST_ASSERT(
            hash_xdp == hash_user,
            "%s: XDP=0x%08X == User=0x%08X",
            test_cases[i].name,
            hash_xdp,
            hash_user
        );
    }
}

static void test_edge_cases(void) {
    printf("\n[TEST] Edge Cases\n");

    // Empty name (just root)
    __u8 pkt_root[] = { 0x00 };
    void* cursor = pkt_root;
    __u32 hash = 0;
    int ret = calculate_dns_name_hash_xdp(&cursor, pkt_root + sizeof(pkt_root), &hash);
    TEST_ASSERT(ret == 0, "root name accepted");
    TEST_ASSERT(hash == FNV_OFFSET_BASIS_32, "root hash = FNV_OFFSET_BASIS_32");

    // Single label
    __u8 pkt_single[] = { 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00 };
    cursor = pkt_single;
    hash = 0;
    ret = calculate_dns_name_hash_xdp(&cursor, pkt_single + sizeof(pkt_single), &hash);
    TEST_ASSERT(ret == 0, "single label accepted");
    TEST_ASSERT(hash != FNV_OFFSET_BASIS_32, "single label hash != FNV_OFFSET_BASIS_32");

    // Flatten with NULL dest (just measure length)
    __u8 pkt[] = { 0x03, 'w', 'w', 'w', 0x00 };
    int len = flatten_name_impl(pkt, 0, sizeof(pkt), NULL, 0);
    TEST_ASSERT(len == 5, "flatten measure only: len=%d (expected 5)", len);
}

int main(void) {
    printf("========================================\n");
    printf("DNS Hash & Flatten Test Suite\n");
    printf("========================================\n");

    test_xdp_basic_names();
    test_xdp_compression_rejected();
    test_xdp_case_normalization();
    test_xdp_bounds_check();
    test_user_space_compression();
    test_flatten_name();
    test_consistency_xdp_vs_user();
    test_edge_cases();

    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", pass_count, test_count);
    printf("========================================\n");

    return (pass_count == test_count) ? 0 : 1;
}
