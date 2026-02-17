#include "parser.h"
#include <common/constants.h>
#include <common/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

static inline void write_u16(uint8_t* ptr, uint16_t val) {
    val = htons(val);
    memcpy(ptr, &val, 2);
}

static inline uint16_t read_u16(const uint8_t* ptr) {
    uint16_t val;
    memcpy(&val, ptr, 2);
    return ntohs(val);
}

// For internal use and testing
int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    int current_offset = offset;
    int jumped = 0;
    int count = 0;
    int consumed_len = 0;

    while (count++ < MAX_DNS_LABEL_ITERATIONS) {
        if (current_offset >= max_len)
            return -1;
        unsigned char len = packet[current_offset];

        if (len == 0) { // Case A: End
            if (!jumped)
                consumed_len++;
            current_offset++;
            break;
        }

        if ((len & 0xC0) == 0xC0) { // Case B: Pointer
            if (current_offset + 1 >= max_len)
                return -1;
            int ptr_val = ((len & 0x3F) << 8) | packet[current_offset + 1];
            if (!jumped)
                consumed_len += 2;
            current_offset = ptr_val; // Jump
            jumped = 1;
            continue;
        }

        // Case C: Label
        if (!jumped)
            consumed_len += (1 + len);

        // Hash the length byte
        hash ^= len;
        hash *= FNV_PRIME_32;

        current_offset++; // Move to content
        for (int i = 0; i < len; i++) {
            if (current_offset >= max_len)
                return -1;
            unsigned char c = packet[current_offset++];
            // Normalize 'A'-'Z'
            if (c >= 'A' && c <= 'Z')
                c |= 0x20;
            hash ^= c;
            hash *= FNV_PRIME_32;
        }
    }
    *out_hash = hash;
    return consumed_len;
}

// Original static function for internal use only
static int
calculate_hash_strict(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    return calculate_hash_strict_impl(packet, offset, max_len, out_hash);
}

// Decompress the domain name from the packet and write it to dest, returning the length written.
// If dest is NULL, only calculate the length after expansion.
// For internal use and testing
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    int current_offset = offset;
    int written = 0;
    int count = 0;

    while (count++ < MAX_DNS_LABEL_ITERATIONS) {
        if (current_offset >= max_len)
            return -1;
        unsigned char len = packet[current_offset];

        if (len == 0) { // End
            if (dest && written < dest_max)
                dest[written] = 0;
            written++;
            return written;
        }

        if ((len & 0xC0) == 0xC0) { // Pointer
            if (current_offset + 1 >= max_len)
                return -1;
            int ptr_val = ((len & 0x3F) << 8) | packet[current_offset + 1];
            current_offset = ptr_val; // Jump logic
            continue;
        }

        // Label
        if (dest) {
            if (written + 1 + len > dest_max)
                return -1; // Overflow check
            dest[written] = len; // Copy length
            memcpy(dest + written + 1, packet + current_offset + 1, len); // Copy content
        }
        written += (1 + len);
        current_offset += (1 + len);
    }
    return -1; // Loop limit
}

// Original static function for internal use only
static int
flatten_name(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    return flatten_name_impl(packet, offset, max_len, dest, dest_max);
}

int handle_packet(void* ctx, void* data, size_t len) {
    struct dns_event* e = data;
    uint32_t pkt_len = e->len;
    uint8_t* pkt_data = e->payload;

    if (pkt_len < sizeof(struct dns_hdr))
        return 0;

    struct dns_hdr* dns = (struct dns_hdr*)pkt_data;
    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t flags = ntohs(dns->flags);
    uint16_t id = ntohs(dns->id);

    // 1. Basic Filters
    uint8_t is_response = (flags >> 15) & 0x1;
    if (!is_response)
        return 0; // Only process DNS responses, not queries
    if (qdcount != 1)
        return 0;
    if (flags & DNS_FLAG_TC)
        return 0; // Check TC bit (Truncated)
    if ((flags & DNS_RCODE_MASK) != 0)
        return 0; // Only RCODE=0
    if (ancount == 0)
        return 0;

    // 2. Parse Question (Get Hash & Length)
    uint32_t name_hash = 0;
    uint32_t read_offset = sizeof(struct dns_hdr);
    int qname_len_packet = calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash);

    if (qname_len_packet < 0)
        return 0;

    // Read QTYPE/QCLASS
    int q_end = read_offset + qname_len_packet;
    if ((uint32_t)q_end + 4 > pkt_len)
        return 0;
    uint16_t qtype = read_u16(pkt_data + q_end);
    uint16_t qclass = read_u16(pkt_data + q_end + 2);

    // 3. Start Normalization (Building the Flat Buffer)
    uint8_t flat_buf[1500]; // Stack buffer, max MTU
    int flat_offset = 0;

    // 3.1 Copy Header
    memcpy(flat_buf, dns, sizeof(struct dns_hdr));
    struct dns_hdr* flat_hdr = (struct dns_hdr*)flat_buf;
    flat_hdr->arcount = 0; // [Strategy]: Strip Additional Section (ECS/OPT)
    flat_offset += sizeof(struct dns_hdr);

    // 3.2 Flatten Question
    int w_len =
        flatten_name(pkt_data, read_offset, pkt_len, flat_buf + flat_offset, 1500 - flat_offset);
    if (w_len < 0)
        return 0;
    flat_offset += w_len;

    // Copy QTYPE/QCLASS
    write_u16(flat_buf + flat_offset, qtype);
    write_u16(flat_buf + flat_offset + 2, qclass);
    flat_offset += 4;

    // Update read pointer past Question Section
    read_offset = q_end + 4;

    // 3.3 Flatten Answers
    for (int i = 0; i < ancount; i++) {
        // Expand Answer Name
        w_len = flatten_name(
            pkt_data,
            read_offset,
            pkt_len,
            flat_buf + flat_offset,
            1500 - flat_offset
        );
        if (w_len < 0)
            return 0;

        // Update pointers
        // flatten_name doesn't tell us how many bytes we consumed in SOURCE packet (because of jumps)
        // We need a helper or just re-calculate source consumption.
        // For simplicity here, assume we use a "skip_name" helper logic:
        int skip_len =
            calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash); // hash ignored
        read_offset += skip_len;
        flat_offset += w_len;

        // Read Record Header (Type, Class, TTL, RDLen)
        if (read_offset + 10 > pkt_len)
            return 0;
        struct dns_record_hdr {
            uint16_t t, c;
            uint32_t ttl;
            uint16_t l;
        } __attribute__((packed));
        struct dns_record_hdr* rh = (void*)(pkt_data + read_offset);

        uint16_t rtype = ntohs(rh->t);
        uint16_t rdlen = ntohs(rh->l);

        // Write Header to Flat Buf (Keep TTL, etc)
        if (flat_offset + 10 > 1500)
            return 0;
        memcpy(flat_buf + flat_offset, pkt_data + read_offset, 8); // Type, Class, TTL
        flat_offset += 8;

        // Handle RDATA
        // If it's CNAME/PTR (Type 5 or 12), RDATA also contains compressed pointers, which need to be flattened as well!
        // If it's A/AAAA, just copy it.
        read_offset += 10; // moved past header

        if (read_offset + rdlen > pkt_len)
            return 0;

        if (rtype == DNS_TYPE_A) { // simplify: ignore DNS_TYPE_AAAA and DNS_TYPE_TXT
            write_u16(flat_buf + flat_offset, rdlen); // Write RDLen
            flat_offset += 2;
            memcpy(flat_buf + flat_offset, pkt_data + read_offset, rdlen); // Write IP
            flat_offset += rdlen;
        } else {
            // For V1, simplify: Don't cache complex records requiring RDATA expansion
            // Or handle CNAME flattening here.
            return 0; // Skip caching complex types for now
        }
        read_offset += rdlen;
    }

    // 4. Update BPF Arena & Map
    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    // Call your allocator
    // void* arena_ptr = arena_alloc(flat_offset);
    // memcpy(arena_ptr, flat_buf, flat_offset);
    // bpf_map_update_elem(..., &key, &arena_ptr, ...);

    printf("[Cache] Stored Normalized DNS. Hash=0x%x Size=%d\n", name_hash, flat_offset);
    return 0;
}
