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

/**
 * @brief Testable wrapper for calculate_dns_name_hash.
 * @param cursor Input/output: pointer to start of QNAME.
 * @param data_end Pointer to end of data.
 * @param hash_out Output: calculated hash.
 * @return 0 on success, -1 on error.
 *
 * @note This function exists solely to export the inline function
 *       from hash.h for unit testing. In production BPF code, the
 *       inline version is used directly.
 */
int calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out) {
    return calculate_dns_name_hash(cursor, data_end, hash_out);
}
