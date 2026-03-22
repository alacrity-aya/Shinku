// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static uint32_t ring_buffer_alloc(uint32_t* next_idx, uint32_t max_entries) {
    uint32_t idx = atomic_fetch_add_explicit((atomic_uint*)next_idx, 1, memory_order_relaxed);
    return idx % max_entries;
}

static void test_sequential_allocation(void) {
    printf("\n--- Test: Sequential Allocation ---\n");
    uint32_t max = 10;
    uint32_t next_idx = 0;

    for (int i = 0; i < 5; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == (uint32_t)i, "Allocation %d should get index %d (got %u)", i, i, idx);
    }

    TEST_ASSERT(next_idx == 5, "next_idx should be 5 after 5 allocations (got %u)", next_idx);
}

static void test_wrap_around(void) {
    printf("\n--- Test: Wrap-Around ---\n");
    uint32_t max = 5;
    uint32_t next_idx = 0;

    for (uint32_t i = 0; i < max; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == i, "Pre-wrap allocation %u should get index %u", i, i);
    }

    TEST_ASSERT(next_idx == max, "next_idx should be %u after filling (got %u)", max, next_idx);

    uint32_t wrap_idx = ring_buffer_alloc(&next_idx, max);
    TEST_ASSERT(wrap_idx == 0, "First wrap allocation should get index 0 (got %u)", wrap_idx);
    TEST_ASSERT(next_idx == max + 1, "next_idx should be %u after wrap (got %u)", max + 1, next_idx);

    uint32_t wrap_idx2 = ring_buffer_alloc(&next_idx, max);
    TEST_ASSERT(wrap_idx2 == 1, "Second wrap allocation should get index 1 (got %u)", wrap_idx2);
}

static void test_multiple_wrap_arounds(void) {
    printf("\n--- Test: Multiple Wrap-Arounds ---\n");
    uint32_t max = 3;
    uint32_t next_idx = 0;

    for (int cycle = 0; cycle < 3; cycle++) {
        for (uint32_t i = 0; i < max; i++) {
            uint32_t idx = ring_buffer_alloc(&next_idx, max);
            uint32_t expected = (cycle * max + i) % max;
            TEST_ASSERT(idx == expected, "Cycle %d, alloc %u: expected %u, got %u", cycle, i, expected, idx);
        }
    }

    TEST_ASSERT(next_idx == max * 3, "next_idx should be %u after 3 cycles (got %u)", max * 3, next_idx);
}

static void test_index_modulo_large_values(void) {
    printf("\n--- Test: Index Modulo (Large Values) ---\n");
    uint32_t max = 10;
    uint32_t next_idx = UINT32_MAX - 5;

    uint32_t idx1 = ring_buffer_alloc(&next_idx, max);
    uint32_t expected1 = (UINT32_MAX - 5) % max;
    TEST_ASSERT(idx1 == expected1, "First large index should be %u (got %u)", expected1, idx1);

    uint32_t idx2 = ring_buffer_alloc(&next_idx, max);
    uint32_t expected2 = (UINT32_MAX - 4) % max;
    TEST_ASSERT(idx2 == expected2, "Second large index should be %u (got %u)", expected2, idx2);

    TEST_ASSERT(next_idx == UINT32_MAX - 3, "next_idx should wrap correctly near UINT32_MAX");
}

static void test_boundary_conditions(void) {
    printf("\n--- Test: Boundary Conditions ---\n");
    uint32_t max = 4;
    uint32_t next_idx = 0;

    for (uint32_t i = 0; i < max - 1; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == i, "Boundary test alloc %u", i);
    }

    TEST_ASSERT(next_idx == max - 1, "next_idx at max-1 boundary (got %u)", next_idx);

    uint32_t idx_at_boundary = ring_buffer_alloc(&next_idx, max);
    TEST_ASSERT(idx_at_boundary == max - 1, "Last slot before wrap (got %u)", idx_at_boundary);

    uint32_t idx_wrapped = ring_buffer_alloc(&next_idx, max);
    TEST_ASSERT(idx_wrapped == 0, "First wrapped index should be 0 (got %u)", idx_wrapped);
}

#define NUM_THREADS 4
#define ALLOCS_PER_THREAD 1000

struct thread_arg {
    uint32_t* next_idx;
    uint32_t max_entries;
    uint32_t allocated_indices[ALLOCS_PER_THREAD];
};

static void* thread_allocator(void* arg) {
    struct thread_arg* ta = (struct thread_arg*)arg;

    for (int i = 0; i < ALLOCS_PER_THREAD; i++) {
        ta->allocated_indices[i] = ring_buffer_alloc(ta->next_idx, ta->max_entries);
    }

    return NULL;
}

static void test_concurrent_allocation(void) {
    printf("\n--- Test: Concurrent Allocation ---\n");
    uint32_t max = 10000;
    uint32_t next_idx = 0;

    pthread_t threads[NUM_THREADS];
    struct thread_arg args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].next_idx = &next_idx;
        args[i].max_entries = max;
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        int ret = pthread_create(&threads[i], NULL, thread_allocator, &args[i]);
        TEST_ASSERT(ret == 0, "Thread %d created successfully", i);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    uint32_t expected_total = NUM_THREADS * ALLOCS_PER_THREAD;
    TEST_ASSERT(next_idx == expected_total, "Total allocations should be %u (got %u)", expected_total, next_idx);

    int all_valid = 1;
    for (int t = 0; t < NUM_THREADS; t++) {
        for (int i = 0; i < ALLOCS_PER_THREAD; i++) {
            if (args[t].allocated_indices[i] >= max) {
                all_valid = 0;
                break;
            }
        }
    }
    TEST_ASSERT(all_valid, "All allocated indices should be < max_entries");
}

static void test_single_entry_ring(void) {
    printf("\n--- Test: Single Entry Ring ---\n");
    uint32_t max = 1;
    uint32_t next_idx = 0;

    for (int i = 0; i < 5; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == 0, "Single entry ring should always return 0 (got %u)", idx);
    }

    TEST_ASSERT(next_idx == 5, "next_idx should be 5 (got %u)", next_idx);
}

static void test_large_ring_buffer(void) {
    printf("\n--- Test: Large Ring Buffer ---\n");
    uint32_t max = 1000;
    uint32_t next_idx = 0;

    for (uint32_t i = 0; i < max; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == i, "Large ring alloc %u", i);
    }

    TEST_ASSERT(next_idx == max, "next_idx should be %u (got %u)", max, next_idx);

    for (uint32_t i = 0; i < 10; i++) {
        uint32_t idx = ring_buffer_alloc(&next_idx, max);
        TEST_ASSERT(idx == i, "Wrapped alloc %u should get index %u", i, i);
    }
}

static void test_power_of_two_sizes(void) {
    printf("\n--- Test: Power-of-Two Sizes ---\n");
    uint32_t sizes[] = {2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    int all_passed = 1;

    for (int s = 0; s < num_sizes; s++) {
        uint32_t max = sizes[s];
        uint32_t next_idx = 0;

        for (uint32_t i = 0; i < max + 5; i++) {
            uint32_t idx = ring_buffer_alloc(&next_idx, max);
            uint32_t expected = i % max;
            if (idx != expected) {
                all_passed = 0;
                break;
            }
        }
    }
    TEST_ASSERT(all_passed, "All power-of-two sizes tested successfully");
}

static void test_prime_sizes(void) {
    printf("\n--- Test: Prime Sizes ---\n");
    uint32_t sizes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 97, 101, 103};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    int all_passed = 1;

    for (int s = 0; s < num_sizes; s++) {
        uint32_t max = sizes[s];
        uint32_t next_idx = 0;

        for (uint32_t i = 0; i < max + 5; i++) {
            uint32_t idx = ring_buffer_alloc(&next_idx, max);
            uint32_t expected = i % max;
            if (idx != expected) {
                all_passed = 0;
                break;
            }
        }
    }
    TEST_ASSERT(all_passed, "All prime sizes tested successfully");
}

int main(void) {
    printf("========================================\n");
    printf("Ring Buffer Allocator Tests\n");
    printf("========================================\n");

    test_sequential_allocation();
    test_wrap_around();
    test_multiple_wrap_arounds();
    test_index_modulo_large_values();
    test_boundary_conditions();
    test_concurrent_allocation();
    test_single_entry_ring();
    test_large_ring_buffer();
    test_power_of_two_sizes();
    test_prime_sizes();

    printf("\n========================================\n");
    printf("Results: %d/%d tests passed\n", pass_count, test_count);
    printf("========================================\n");

    return (pass_count == test_count) ? 0 : 1;
}
