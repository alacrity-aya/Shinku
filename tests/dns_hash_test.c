// tests/dns_hash_test.c
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#ifndef __always_inline
    #define __always_inline inline
#endif

#define FNV_OFFSET_BASIS_32 2166136261U
#define FNV_PRIME_32 16777619U
#define MAX_DNS_NAME_LEN 255
#define MAX_COMPRESSION_JUMPS 10

#define LOG_DBG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

uint32_t calculate_dns_name_hash_user(const uint8_t* packet, size_t packet_len, size_t* offset) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    size_t current_pos = *offset;
    int jumped = 0;
    int jumps_count = 0;

    while (1) {
        if (current_pos >= packet_len)
            return 0;
        uint8_t len_byte = packet[current_pos];

        if (len_byte == 0) {
            if (!jumped)
                *offset = current_pos + 1;
            break;
        }

        if ((len_byte & 0xC0) == 0xC0) {
            if (current_pos + 1 >= packet_len)
                return 0;

            uint16_t ptr_val = ntohs(*(uint16_t*)(packet + current_pos));
            uint16_t jump_offset = ptr_val & 0x3FFF;

            if (jump_offset >= packet_len)
                return 0;

            if (!jumped) {
                *offset = current_pos + 2;
                jumped = 1;
            }

            jumps_count++;
            if (jumps_count > MAX_COMPRESSION_JUMPS)
                return 0;

            current_pos = jump_offset;
            continue;
        }

        hash ^= len_byte;
        hash *= FNV_PRIME_32;
        current_pos++;

        for (int i = 0; i < len_byte; i++) {
            if (current_pos >= packet_len)
                return 0;
            uint8_t b = packet[current_pos];
            if (b >= 'A' && b <= 'Z')
                b |= 0x20;

            hash ^= b;
            hash *= FNV_PRIME_32;
            current_pos++;
        }

        if (!jumped)
            *offset = current_pos;
    }
    return hash;
}

static __always_inline int
calculate_dns_name_hash_xdp(void** cursor, void* data_end, __u32* hash_out) {
    void* ptr = *cursor;
    __u32 hash = FNV_OFFSET_BASIS_32;
    int label_bytes_remaining = 0;

    LOG_DBG("XDP Start: ptr=%p, data_end=%p, diff=%ld", ptr, data_end, (long)(data_end - ptr));

    for (int i = 0; i < MAX_DNS_NAME_LEN; i++) {
        if (ptr + 1 > data_end) {
            LOG_DBG(
                "XDP Error: Bounds check failed at index %d. ptr=%p, data_end=%p",
                i,
                ptr,
                data_end
            );
            return -1;
        }

        __u8 byte = *(__u8*)ptr;
        LOG_DBG(
            "Loop %d: Byte=0x%02X (%c), Remaining=%d, CurrentHash=0x%X",
            i,
            byte,
            (byte >= 32 && byte <= 126) ? byte : '.',
            label_bytes_remaining,
            hash
        );

        if (label_bytes_remaining > 0) {
            // Case A: Content
            if (byte >= 'A' && byte <= 'Z') {
                byte |= 0x20;
            }
            hash ^= byte;
            hash *= FNV_PRIME_32;
            label_bytes_remaining--;
        } else {
            // Case B: Length
            if (byte == 0) {
                LOG_DBG("XDP Success: Found 0x00 at index %d. Final Hash=0x%X", i, hash);
                ptr++; // Skip the 0x00
                *cursor = ptr;
                *hash_out = hash;
                return 0; // Success
            }

            if ((byte & 0xC0) == 0xC0) {
                LOG_DBG(
                    "XDP Error: Compression pointer 0x%02X found at index %d (not supported)",
                    byte,
                    i
                );
                return -1;
            }

            label_bytes_remaining = byte;
            LOG_DBG("  -> New Label Length: %d", label_bytes_remaining);

            // Hash length byte
            hash ^= byte;
            hash *= FNV_PRIME_32;
        }
        ptr++;
    }

    LOG_DBG("XDP Error: Loop exhausted (MAX_DNS_NAME_LEN reached)");
    return -1; // Name too long
}

void test_consistency(
    const char* name,
    const uint8_t* compressed_pkt,
    size_t c_len,
    size_t c_start_off,
    const uint8_t* flat_pkt,
    size_t f_len
) {
    printf("\n------------------------------------------------------------\n");
    printf("Test Case: %-20s \n", name);
    printf("------------------------------------------------------------\n");

    size_t user_offset = c_start_off;
    uint32_t hash_user = calculate_dns_name_hash_user(compressed_pkt, c_len, &user_offset);
    printf("User Space Hash: 0x%08X (Offset end: %zu)\n", hash_user, user_offset);

    printf("XDP Input Data (%zu bytes): ", f_len);
    for (size_t i = 0; i < f_len; i++)
        printf("%02X ", flat_pkt[i]);
    printf("\n");

    void* cursor = (void*)flat_pkt;
    void* data_end = (void*)(flat_pkt + f_len);
    __u32 hash_xdp = 0;

    int ret = calculate_dns_name_hash_xdp(&cursor, data_end, &hash_xdp);

    if (ret != 0) {
        printf(">>> FAIL (XDP Error: %d)\n", ret);
        exit(1);
    }
    if (hash_user == 0) {
        printf(">>> FAIL (User Error: Hash is 0)\n");
        exit(1);
    }
    if (hash_user != hash_xdp) {
        printf(">>> FAIL (Mismatch!)\n");
        printf("    User: 0x%08X\n", hash_user);
        printf("    XDP : 0x%08X\n", hash_xdp);
        exit(1);
    }

    printf(">>> PASS (Hash: 0x%08X)\n", hash_user);
}

int main() {
    uint8_t pkt_c[100] = { 0 };
    memcpy(
        &pkt_c[10],
        "\x06google\x03"
        "com\x00",
        12
    );
    pkt_c[30] = 4;
    memcpy(&pkt_c[31], "mail", 4);
    pkt_c[35] = 0xC0;
    pkt_c[36] = 10;

    uint8_t pkt_f[] =
        "\x04mail\x06google\x03"
        "com\x00";

    test_consistency("mail.google.com", pkt_c, sizeof(pkt_c), 30, pkt_f, sizeof(pkt_f) - 1);

    uint8_t pkt_simple[] =
        "\x03www\x07"
        "example\x03"
        "com\x00";

    test_consistency(
        "www.example.com",
        pkt_simple,
        sizeof(pkt_simple) - 1,
        0,
        pkt_simple,
        sizeof(pkt_simple) - 1
    );

    return 0;
}
