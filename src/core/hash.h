// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#if defined(__BPF__) && __BPF__
    #include <bpf/bpf_helpers.h>
    #include <vmlinux.h>
#else
    #include <linux/types.h>
#endif

#include "constants.h"

/**
 * @file hash.h
 * @brief FNV-1a hash implementation for DNS names.
 *
 * This header provides a BPF-compatible hash function for DNS domain names.
 * The implementation is designed for XDP fast path with the following constraints:
 *   - No compression pointer support (rejected for safety)
 *   - Bounded loop iteration (MAX_DNS_NAME_LEN = 255)
 *   - Case-insensitive hashing (per RFC 1035)
 */

/**
 * @brief Calculate FNV-1a hash of a DNS domain name.
 * @param cursor Input/output: pointer to start of QNAME, updated to end of name.
 * @param data_end Pointer to end of packet data (for bounds checking).
 * @param hash_out Output: calculated 32-bit hash value.
 * @return 0 on success, -1 on truncation or compression pointer.
 *
 * Reads the DNS name byte-by-byte, hashing each label content with FNV-1a.
 * Case normalization is performed inline ('A'-'Z' -> 'a'-'z').
 *
 * @note Compression pointers (0xC0 prefix) are rejected with -1.
 *       This is intentional for XDP safety - compression requires
 *       arbitrary seeks which are problematic in BPF context.
 *
 * @note The length byte of each label is also hashed, ensuring
 *       "example.com" and "exa.mple.com" produce different hashes.
 */
static __always_inline int calculate_dns_name_hash(void** cursor, void* data_end, __u32* hash_out) {
    void* ptr = *cursor;
    __u32 hash = FNV_OFFSET_BASIS_32;

    /* State: how many bytes of current label remain.
     * 0 = expecting a Length byte (or End byte 0x00) */
    int label_bytes_remaining = 0;

/* Flattened loop: iterate byte-by-byte, max 255 times.
 * This linear complexity satisfies the BPF verifier. */
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
        /* Bounds check */
        if (ptr + 1 > data_end)
            return -1;

        __u8 byte = *(__u8*)ptr;

        if (label_bytes_remaining > 0) {
            /* Case A: Reading label content (e.g., 'w', 'w', 'w') */

            /* Normalize: 'A'-'Z' -> 'a'-'z' */
            if (byte >= 'A' && byte <= 'Z') {
                byte |= 0x20;
            }

            /* FNV-1a Hash Step */
            hash ^= byte;
            hash *= FNV_PRIME_32;

            label_bytes_remaining--;
        } else {
            /* Case B: Reading a Length byte (e.g., 3, 6, or 0) */

            if (byte == 0) {
                /* End of QNAME (Root Label) */
                ptr++;
                *cursor = ptr;
                *hash_out = hash;
                return 0;
            }

            /* Check for Compression Pointer (11xxxxxx -> >= 0xC0) */
            if ((byte & 0xC0) == 0xC0) {
                return -1; /* Not supported in XDP fast path */
            }

            /* Set state for next N bytes */
            label_bytes_remaining = byte;

            /* Hash the length byte to prevent collisions between
             * "ab" (1a1b0) and "a.b" (1a1b0) - wait, they're the same!
             * Actually this ensures "exa" vs "e.x.a" differ. */
            hash ^= byte;
            hash *= FNV_PRIME_32;
        }

        ptr++;
    }

    return -1; /* Name too long (exceeded 255 bytes) */
}

/* ============================================================================
 * Userspace Test Interface
 * ============================================================================ */

#if !defined(__BPF__) || __BPF__ == 0
/**
 * @brief Userspace wrapper for calculate_dns_name_hash (for unit testing).
 * @param cursor Input/output: pointer to start of QNAME.
 * @param data_end Pointer to end of data.
 * @param hash_out Output: calculated hash.
 * @return 0 on success, -1 on error.
 * @note Implemented in hash.c.
 */
int hash_calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out);

/**
 * @brief Legacy alias for hash_calculate_dns_name_hash_test.
 * @param cursor Input/output: pointer to start of QNAME.
 * @param data_end Pointer to end of data.
 * @param hash_out Output: calculated hash.
 * @return 0 on success, -1 on error.
 * @deprecated Use hash_calculate_dns_name_hash_test() instead.
 */
int calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out);
#endif
