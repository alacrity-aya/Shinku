// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

/**
 * @file hash.c
 * @brief Testable wrapper for FNV-1a hash functions.
 *
 * This file provides a non-static, exported version of the hash function
 * for userspace unit testing. The main implementation is in hash.h as a
 * static inline function for BPF compatibility.
 */

#include "hash.h"

int hash_calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out) {
    return calculate_dns_name_hash(cursor, data_end, hash_out);
}
