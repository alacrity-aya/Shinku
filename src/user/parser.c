#include "parser.h"
#include <common/constants.h>
#include <common/types.h>
#include <netinet/in.h>
#include <stdint.h>

static int
calculate_hash_from_response(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    int current_offset = offset;
    int jumped = 0; // Flag to indicate if a jump (compression pointer) has occurred
    int count = 0; // Loop counter to prevent infinite loops

    /* * Used for return value: 
     * If no jump occurred, the QNAME length is the total scanned length.
     * If a jump occurred, the length is only calculated up to the pointer location.
     */
    int consumed_len = 0;

    while (count++ < 100) { // Limit iterations to prevent malicious packets
        if (current_offset >= max_len)
            return -1;

        unsigned char len = packet[current_offset];

        // Case A: Terminator (0x00)
        if (len == 0) {
            /* * Hash ends (Note: In the XDP code, if the byte is 0, the hash logic ends. 
             * The 0 itself is not hashed; only the label content is hashed).
             * According to your hash.h: if (byte == 0) { ... return 0; } -> 0 is not hashed.
             */

            if (!jumped)
                consumed_len++;
            current_offset++;
            break;
        }

        // Case B: Compression Pointer (11xxxxxx)
        if ((len & 0xC0) == 0xC0) {
            if (current_offset + 1 >= max_len)
                return -1;

            // Read the new offset pointed to by the compression pointer
            int ptr_val = ((len & 0x3F) << 8) | packet[current_offset + 1];

            // If we haven't jumped yet, the consumed length must include these 2 bytes
            if (!jumped) {
                consumed_len += 2;
            }

            // Execute the jump
            current_offset = ptr_val;
            jumped = 1;
            continue; // Continue loop to read content from the new position
        }

        // Case C: Standard Label
        // 'len' is the length of the label
        if (!jumped)
            consumed_len += (1 + len); // Length byte + actual content

        current_offset++; // Skip the length byte

        for (int i = 0; i < len; i++) {
            if (current_offset >= max_len)
                return -1;

            unsigned char c = packet[current_offset++];

            if (c >= 'A' && c <= 'Z') {
                c |= 0x20;
            }

            hash ^= c;
            hash *= FNV_PRIME_32;
        }
    }

    *out_hash = hash;
    /* * Return to caller to indicate how much space the QNAME occupied 
     * so it can jump to the QTYPE section.
     */
    return consumed_len;
}

int handle_packet(void* ctx, void* data, [[maybe_unused]] size_t len) {
    struct dns_event* e = data;
    uint32_t pkt_len = e->len;
    uint8_t* pkt_data = e->payload;

    if (pkt_len < sizeof(struct dns_hdr)) [[clang::unlikely]] {
        return 0;
    }

    printf("[Packet] Captured DNS Response! Len=%d Timestamp=%llu\n", e->len, e->timestamp);

    // TODO: parse dns here

    struct dns_hdr* dns = (struct dns_hdr*)e->payload;
    uint32_t offset = sizeof(struct dns_hdr);

    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t flags = ntohs(dns->flags);
    uint16_t id = ntohs(dns->id);

    if (qdcount != 1) {
        printf("[Info] Ignored packet with QDCOUNT=%d (XDP requires 1)\n", qdcount);
        return 0;
    }

    uint8_t rcode = flags & 0x0F;

    if (rcode != 0) {
        /*
         * 0 = No Error (Success)
         * 3 = NXDOMAIN (Domain does not exist) -> Potential for Negative Caching
         * 2 = SERVFAIL (Server Failure) -> Do not cache
         * 5 = REFUSED -> Do not cache
         */

        // Current Policy: Only cache successful resolutions
        printf("[Info] DNS Error RCODE=%d for ID=0x%04x. Skipping cache.\n", rcode, id);
        return 0;
    }

    if (ancount == 0) {
        return 0;
    }

    uint32_t name_hash = 0;
    int qname_len = calculate_hash_from_response(pkt_data, offset, pkt_len, &name_hash);

    if (qname_len < 0) {
        return 0; // Failed to parse domain name
    }

    // Skip QNAME
    offset += qname_len;

    // Check for QTYPE(2 bytes) + QCLASS(2 bytes)
    if (offset + 4 > pkt_len)
        return 0;

    uint16_t qtype = ntohs(*(uint16_t*)(pkt_data + offset));
    uint16_t qclass = ntohs(*(uint16_t*)(pkt_data + offset + 2));
    offset += 4; // Skip QTYPE and QCLASS

    // Construct the Cache Key
    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    // TODO: write into bpf_arena

    return 0;
}
