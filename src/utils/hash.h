#pragma once

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <common/constants.h>

// Calculate FNV-1a hash of a DNS domain name
// Input: cursor (points to the start of QNAME), data_end
// Output: hash_out (the resulting hash value)
// Returns: 0 on success, -1 on truncation/failure.
// Updates cursor to point past the end of QNAME (immediately after the 0x00 terminator).
static __always_inline int calculate_dns_name_hash(void** cursor, void* data_end, __u32* hash_out) {
    void* ptr = *cursor;
    __u32 hash = FNV_OFFSET_BASIS_32;

    // State variable: How many bytes of the current label are remaining?
    // 0 means we are expecting a Length byte (or End byte 0x00)
    int label_bytes_remaining = 0;

// Flattened loop: Iterate byte by byte, max 255 times
// This linear complexity makes the Verifier happy.
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
        // Bounds check
        if (ptr + 1 > data_end)
            return -1;

        __u8 byte = *(__u8*)ptr;

        if (label_bytes_remaining > 0) {
            // Case A: We are reading Content (e.g., 'w', 'w', 'w')

            // Normalize: 'A'-'Z' -> 'a'-'z'
            if (byte >= 'A' && byte <= 'Z') {
                byte |= 0x20;
            }

            // FNV-1a Hash Step
            hash ^= byte;
            hash *= FNV_PRIME_32;

            label_bytes_remaining--;
        } else {
            // Case B: We are reading a Length byte (e.g., 3, 6, or 0)

            if (byte == 0) {
                // End of QNAME (Root Label)
                // Move cursor past this 0 byte and return success
                ptr++;
                *cursor = ptr;
                *hash_out = hash;
                return 0;
            }

            // Check for Compression Pointer (11xxxxxx -> >= 0xC0)
            if ((byte & 0xC0) == 0xC0) {
                return -1; // Not supported in XDP fast path
            }

            // Set state for the next N bytes
            label_bytes_remaining = byte;

            // Optional: Hash the length byte/separator to prevent collision
            // between "ab" (1a1b0) and "a.b" (1a1b0).
            // The wire format includes length bytes, so hashing them ensures uniqueness.
            hash ^= byte;
            hash *= FNV_PRIME_32;
        }

        ptr++;
    }

    return -1; // Name too long (exceeded 255 bytes)
}
