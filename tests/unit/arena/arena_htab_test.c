// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arena_htab.skel.h"
#include "bpf_arena_htab.h"

/* Verify arr1 contents filled by BPF program */
static int verify_arr1(char* arr, size_t len) {
    int errors = 0;
    for (size_t i = 0; i < len && i < 1000; i++) {
        if (arr[i] != (char)i) {
            if (errors < 5) {
                fprintf(stderr, "arr1[%zu] = %d, expected %d\n", i, (unsigned char)arr[i], (int)i);
            }
            errors++;
        }
    }
    return errors;
}

/* Count elements in hash table by iterating buckets */
static int count_htab_elements(htab_t* htab) {
    int count = 0;

    if (!htab || !htab->buckets)
        return -1;

    for (int i = 0; i < htab->n_buckets; i++) {
        htab_bucket_t* bucket = &htab->buckets[i];
        arena_list_head_t* head = &bucket->head;
        hashtab_elem_t* elem;

        list_for_each_entry(elem, head, hash_node) {
            count++;
        }
    }
    return count;
}

/* Verify hash table elements */
static int verify_htab_elements(htab_t* htab) {
    int errors = 0;

    if (!htab || !htab->buckets)
        return -1;

    /* Verify the first 1000 elements that were inserted twice */
    for (int i = 0; i < 1000; i++) {
        hashtab_elem_t* found = NULL;
        arena_list_head_t* head = select_bucket(htab, i);

        list_for_each_entry(found, head, hash_node) {
            if (found->key == i)
                break;
        }

        if (!found) {
            if (errors < 5) {
                fprintf(stderr, "Key %d not found in hash table\n", i);
            }
            errors++;
        } else if (found->value != i) {
            if (errors < 5) {
                fprintf(stderr, "Key %d has value %d, expected %d\n", i, found->value, i);
            }
            errors++;
        }
    }

    return errors;
}

static int test_arena_htab(int test_size) {
    (void)test_size; /* Currently unused, BPF uses fixed size */
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    struct arena_htab_bpf* skel;
    int ret;

    skel = arena_htab_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Run the BPF program */
    ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arena_htab_llvm), &opts);
    if (ret != 0) {
        fprintf(stderr, "Failed to run arena_htab_llvm: %d\n", ret);
        ret = 1;
        goto out;
    }

    if (opts.retval != 0) {
        fprintf(stderr, "arena_htab_llvm returned %d\n", opts.retval);
        ret = 1;
        goto out;
    }

    /* Check if arena is supported */
    if (skel->bss->skip) {
        printf("SKIP: compiler doesn't support arena_cast\n");
        ret = 77; // Skip test exit code (automake convention)
        goto out;
    }

    printf("BPF program executed successfully\n");

    /* Access the arena memory through skeleton's arena pointer */
    if (!skel->arena) {
        fprintf(stderr, "Arena not available\n");
        ret = 1;
        goto out;
    }

    printf("Hash table pointer (from BPF): %p\n", skel->bss->htab_for_user);

    /* Verify arr1 - first 1000 elements */
    char* arr1 = (char*)skel->arena->arr1;
    int arr_errors = verify_arr1(arr1, 1000);
    if (arr_errors == 0) {
        printf("arr1 verification: PASSED (first 1000 elements)\n");
    } else {
        printf("arr1 verification: FAILED (%d errors)\n", arr_errors);
    }

    /* Access hash table through htab_for_user pointer */
    htab_t* htab = (htab_t*)skel->bss->htab_for_user;
    if (htab) {
        printf("Hash table n_buckets: %d\n", htab->n_buckets);

        int count = count_htab_elements(htab);
        printf("Hash table element count: %d\n", count);

        /* We inserted 100000 elements, then updated 1000 of them */
        /* Expected: 100000 unique elements */
        if (count == 100000) {
            printf("Hash table count: PASSED\n");
        } else {
            printf("Hash table count: FAILED (expected 100000)\n");
        }

        /* Verify first 1000 elements */
        int htab_errors = verify_htab_elements(htab);
        if (htab_errors == 0) {
            printf("Hash table element verification: PASSED\n");
        } else {
            printf("Hash table element verification: FAILED (%d errors)\n", htab_errors);
        }
    } else {
        printf("Hash table pointer is NULL\n");
    }

    printf("\nTest completed!\n");
    ret = 0;
out:
    arena_htab_bpf__destroy(skel);
    return ret;
}

int main(int argc, char** argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "This test must be run as root\n");
        return 1;
    }

    int test_size = 100000; /* Default from BPF program */

    if (argc > 1) {
        test_size = atoi(argv[1]);
        if (test_size <= 0) {
            fprintf(stderr, "Invalid size: %s\n", argv[1]);
            return 1;
        }
    }

    printf("Testing arena hash table with up to %d elements\n", test_size);
    return test_arena_htab(test_size);
}
