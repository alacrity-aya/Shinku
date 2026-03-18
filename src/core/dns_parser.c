// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "dns_parser.h"
#include "constants.h"
#include "types.h"
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static inline void write_u16(uint8_t* ptr, uint16_t val) {
    val = htons(val);
    memcpy(ptr, &val, 2);
}

static inline uint16_t read_u16(const uint8_t* ptr) {
    uint16_t val;
    memcpy(&val, ptr, 2);
    return ntohs(val);
}

static inline uint32_t read_u32(const uint8_t* ptr) {
    uint32_t val;
    memcpy(&val, ptr, 4);
    return ntohl(val);
}

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

        if (len == 0) {
            if (!jumped)
                consumed_len++;
            current_offset++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (current_offset + 1 >= max_len)
                return -1;
            int ptr_val = ((len & 0x3F) << 8) | packet[current_offset + 1];
            if (!jumped)
                consumed_len += 2;
            current_offset = ptr_val;
            jumped = 1;
            continue;
        }

        if (!jumped)
            consumed_len += (1 + len);

        hash ^= len;
        hash *= FNV_PRIME_32;

        current_offset++;
        for (int i = 0; i < len; i++) {
            if (current_offset >= max_len)
                return -1;
            unsigned char c = packet[current_offset++];
            if (c >= 'A' && c <= 'Z')
                c |= 0x20;
            hash ^= c;
            hash *= FNV_PRIME_32;
        }
    }
    *out_hash = hash;
    return consumed_len;
}

static int
calculate_hash_strict(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    return calculate_hash_strict_impl(packet, offset, max_len, out_hash);
}

int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    int current_offset = offset;
    int written = 0;
    int count = 0;

    while (count++ < MAX_DNS_LABEL_ITERATIONS) {
        if (current_offset >= max_len)
            return -1;
        unsigned char len = packet[current_offset];

        if (len == 0) {
            if (dest && written < dest_max)
                dest[written] = 0;
            written++;
            return written;
        }

        if ((len & 0xC0) == 0xC0) {
            if (current_offset + 1 >= max_len)
                return -1;
            int ptr_val = ((len & 0x3F) << 8) | packet[current_offset + 1];
            current_offset = ptr_val;
            continue;
        }

        if (dest) {
            if (written + 1 + len > dest_max)
                return -1;
            dest[written] = len;
            memcpy(dest + written + 1, packet + current_offset + 1, len);
        }
        written += (1 + len);
        current_offset += (1 + len);
    }
    return -1;
}

static int
flatten_name(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    return flatten_name_impl(packet, offset, max_len, dest, dest_max);
}

/* Skip a DNS name in wire format, returning bytes consumed.
 * Re-uses calculate_hash_strict with a throwaway hash. */
static int skip_name(const uint8_t* packet, int offset, int max_len) {
    uint32_t unused_hash;
    return calculate_hash_strict(packet, offset, max_len, &unused_hash);
}

/* Parse OPT RR RDATA for EDNS Client Subnet option.
 * Returns: 0 = no ECS / scope==0 (global), >0 = subnet-specific scope, -1 = parse error */
static int check_ecs_scope(const uint8_t* pkt, int offset, int max_len, int rdlen) {
    int end = offset + rdlen;

    while (offset + 4 <= end && offset + 4 <= max_len) {
        uint16_t opt_code = read_u16(pkt + offset);
        uint16_t opt_len = read_u16(pkt + offset + 2);
        offset += 4;

        if (offset + opt_len > end || offset + opt_len > max_len)
            return -1;

        if (opt_code == EDNS0_OPT_CODE_ECS && opt_len >= 4) {
            /* ECS wire format: FAMILY(2) | SOURCE_PREFIX(1) | SCOPE_PREFIX(1) | ADDRESS... */
            uint8_t scope = pkt[offset + 3];
            return scope;
        }

        offset += opt_len;
    }

    return 0;
}

static int store_to_cache(
    struct cache_ctx* cctx,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
) {
    if (!cctx || !cctx->entries || !cctx->next_idx)
        return -1;

    if (flat_len > ARENA_ENTRY_SIZE || flat_len <= 0)
        return -1;

    uint32_t idx = __sync_fetch_and_add(cctx->next_idx, 1);
    idx %= cctx->max_entries;

    /* Without a valid BPF map fd, we can only update arena, not the map */
    if (cctx->cache_map_fd < 0)
        return -1;

    uint32_t gen = ++cctx->next_gen;

    /* Evict previous occupant of this arena slot if its cache_map entry still
     * points here. Prevents stale cache_map entries from serving wrong data. */
    if (cctx->slot_owners) {
        struct cache_key* old_key = &cctx->slot_owners[idx];
        if (old_key->name_hash != 0 || old_key->qtype != 0) {
            struct cache_value old_val;
            int err = bpf_map_lookup_elem(cctx->cache_map_fd, old_key, &old_val);
            if (err == 0 && old_val.arena_idx == idx) {
                bpf_map_delete_elem(cctx->cache_map_fd, old_key);
            }
        }
    }

    /* Seqlock write: odd seq signals write-in-progress to XDP readers */
    __sync_fetch_and_add(&cctx->entries[idx].seq, 1);

    cctx->entries[idx].gen = gen;
    memcpy(cctx->entries[idx].pkt, flat_buf, flat_len);

    /* Seqlock write complete: even seq signals stable data */
    __sync_fetch_and_add(&cctx->entries[idx].seq, 1);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    struct cache_value val = {
        .arena_idx = idx,
        .expire_ts = now_ns + (uint64_t)min_ttl * 1000000000ULL,
        .pkt_len = (uint16_t)flat_len,
        .scope = ecs_scope,
        .gen = gen,
    };

    /* slot_owners must precede bpf_map_update_elem: arena slot is already written */
    if (cctx->slot_owners)
        cctx->slot_owners[idx] = *key;

    int err = bpf_map_update_elem(cctx->cache_map_fd, key, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "[Cache] bpf_map_update_elem failed: %d\n", err);
        return -1;
    }

    printf(
        "[Cache] Stored: Hash=0x%x Idx=%u Size=%d TTL=%us Gen=%u\n",
        key->name_hash,
        idx,
        flat_len,
        min_ttl,
        gen
    );
    return 0;
}

int cleanup_expired_entries(struct cache_ctx* cctx) {
    if (!cctx || cctx->cache_map_fd < 0)
        return -1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    struct cache_key key = { 0 };
    struct cache_key next_key = { 0 };
    struct cache_value val;

    struct cache_key expired_keys[256];
    int expired_count = 0;

    /* Collect expired keys (can't delete during iteration) */
    int err = bpf_map_get_next_key(cctx->cache_map_fd, NULL, &next_key);
    while (err == 0 && expired_count < 256) {
        key = next_key;
        err = bpf_map_get_next_key(cctx->cache_map_fd, &key, &next_key);

        if (bpf_map_lookup_elem(cctx->cache_map_fd, &key, &val) == 0) {
            if (now_ns >= val.expire_ts) {
                expired_keys[expired_count++] = key;
            }
        }
    }

    for (int i = 0; i < expired_count; i++) {
        if (bpf_map_lookup_elem(cctx->cache_map_fd, &expired_keys[i], &val) == 0) {
            uint32_t idx = val.arena_idx;
            bpf_map_delete_elem(cctx->cache_map_fd, &expired_keys[i]);

            if (cctx->slot_owners && idx < cctx->max_entries) {
                memset(&cctx->slot_owners[idx], 0, sizeof(struct cache_key));
            }
        }
    }

    if (expired_count > 0)
        printf("[Cache] Cleanup: removed %d expired entries\n", expired_count);

    return expired_count;
}

int handle_packet(void* ctx, void* data, [[maybe_unused]] size_t len) {
    struct cache_ctx* cctx = ctx;
    struct dns_event* e = data;
    uint32_t pkt_len = e->len;
    uint8_t* pkt_data = e->payload;

    if (pkt_len < sizeof(struct dns_hdr))
        return 0;

    struct dns_hdr* dns = (struct dns_hdr*)pkt_data;
    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t nscount = ntohs(dns->nscount);
    uint16_t flags = ntohs(dns->flags);

    uint8_t is_response = (flags >> 15) & 0x1;
    if (!is_response)
        return 0;
    if (qdcount != 1)
        return 0;
    if (flags & DNS_FLAG_TC)
        return 0;
    if ((flags & DNS_RCODE_MASK) != 0)
        return 0;
    if (ancount == 0)
        return 0;

    uint32_t name_hash = 0;
    uint32_t read_offset = sizeof(struct dns_hdr);
    int qname_len_packet = calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash);

    if (qname_len_packet < 0)
        return 0;

    int q_end = read_offset + qname_len_packet;
    if ((uint32_t)q_end + 4 > pkt_len)
        return 0;
    uint16_t qtype = read_u16(pkt_data + q_end);
    uint16_t qclass = read_u16(pkt_data + q_end + 2);

    uint8_t flat_buf[1500];
    int flat_offset = 0;

    memcpy(flat_buf, dns, sizeof(*dns));
    struct dns_hdr* flat_hdr = (struct dns_hdr*)flat_buf;
    flat_hdr->arcount = 0;
    flat_hdr->nscount = 0;
    flat_offset += sizeof(struct dns_hdr);

    int w_len =
        flatten_name(pkt_data, read_offset, pkt_len, flat_buf + flat_offset, 1500 - flat_offset);
    if (w_len < 0)
        return 0;
    flat_offset += w_len;

    write_u16(flat_buf + flat_offset, qtype);
    write_u16(flat_buf + flat_offset + 2, qclass);
    flat_offset += 4;

    read_offset = q_end + 4;

    uint32_t min_ttl = UINT32_MAX;
    int has_terminal_rr = 0;

    for (int i = 0; i < ancount; i++) {
        w_len = flatten_name(
            pkt_data,
            read_offset,
            pkt_len,
            flat_buf + flat_offset,
            1500 - flat_offset
        );
        if (w_len < 0)
            return 0;

        int name_skip = skip_name(pkt_data, read_offset, pkt_len);
        if (name_skip < 0)
            return 0;
        read_offset += name_skip;
        flat_offset += w_len;

        if (read_offset + 10 > pkt_len)
            return 0;

        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint32_t ttl = read_u32(pkt_data + read_offset + 4);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);

        if (ttl < min_ttl)
            min_ttl = ttl;

        if (flat_offset + 10 > 1500)
            return 0;
        memcpy(flat_buf + flat_offset, pkt_data + read_offset, 10);
        flat_offset += 10;
        read_offset += 10;

        if (read_offset + rdlen > pkt_len)
            return 0;

        if (rtype == DNS_TYPE_A || rtype == DNS_TYPE_AAAA) {
            if (rtype == qtype)
                has_terminal_rr = 1;
            if (flat_offset + rdlen > 1500)
                return 0;
            memcpy(flat_buf + flat_offset, pkt_data + read_offset, rdlen);
            flat_offset += rdlen;
        } else if (rtype == DNS_TYPE_CNAME) {
            int cname_len = flatten_name(pkt_data, read_offset, pkt_len, NULL, 0);
            if (cname_len < 0)
                return 0;
            if ((uint16_t)cname_len != rdlen)
                return 0;
            if (flat_offset + rdlen > 1500)
                return 0;
            memcpy(flat_buf + flat_offset, pkt_data + read_offset, rdlen);
            flat_offset += rdlen;
        } else {
            return 0;
        }
        read_offset += rdlen;
    }

    if ((qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA) && !has_terminal_rr)
        return 0;

    /* Skip Authority Section */
    for (int i = 0; i < nscount; i++) {
        int name_skip = skip_name(pkt_data, read_offset, pkt_len);
        if (name_skip < 0)
            return 0;
        read_offset += name_skip;
        if (read_offset + 10 > pkt_len)
            return 0;
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10 + rdlen;
    }

    /* Scan Additional Section for OPT RR / ECS */
    uint8_t ecs_scope = 0;
    uint16_t arcount = ntohs(dns->arcount);
    for (int i = 0; i < arcount; i++) {
        int name_skip = skip_name(pkt_data, read_offset, pkt_len);
        if (name_skip < 0)
            return 0;
        read_offset += name_skip;
        if (read_offset + 10 > pkt_len)
            return 0;

        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10;

        if (rtype == DNS_TYPE_OPT) {
            int scope = check_ecs_scope(pkt_data, read_offset, pkt_len, rdlen);
            if (scope > 0)
                return 0;
            if (scope == 0)
                ecs_scope = 0;
        }

        if (read_offset + rdlen > pkt_len)
            return 0;
        read_offset += rdlen;
    }

    if (min_ttl == 0 || min_ttl == UINT32_MAX)
        return 0;

    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    store_to_cache(cctx, &key, flat_buf, flat_offset, min_ttl, ecs_scope);

    return 0;
}
