// This file provides testable versions of hash functions
// It includes the header to get access to the static inline functions
#include "hash.h"
#include <common/constants.h>

// Provide a non-static version of the hash function for testing
int calculate_dns_name_hash_test(void** cursor, void* data_end, __u32* hash_out) {
    return calculate_dns_name_hash(cursor, data_end, hash_out);
}