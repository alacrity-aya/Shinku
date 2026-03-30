// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "dns_parser.h"
#include "cache_ops.h"
#include "constants.h"
#include "types.h"
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DNS_PARSER_FLAT_BUF_SIZE 1500

/** @brief Thread-local buffer for flattening DNS packets */
static _Thread_local uint8_t dns_parser_flat_buf_tls[DNS_PARSER_FLAT_BUF_SIZE];

/**
 * @struct negative_cache_info
 * @brief Parsed information from a negative cache response.
 */
struct negative_cache_info {
    int valid;                   /**< Non-zero if this is a valid negative response */
    enum obs_negative_type type; /**< NXDOMAIN or NODATA */
    uint8_t flags;               /**< Cache entry flags */
    uint32_t ttl;                /**< TTL from SOA minimum field (clamped) */
};

/** @brief Clamp TTL to valid negative cache range (5-600 seconds per RFC 2308) */
static uint32_t clamp_negative_ttl(uint32_t ttl) {
    if (ttl < NEGATIVE_TTL_MIN)
        return NEGATIVE_TTL_MIN;
    if (ttl > NEGATIVE_TTL_MAX)
        return NEGATIVE_TTL_MAX;
    return ttl;
}

/** @brief Write a 16-bit value in network byte order */
static inline void write_u16(uint8_t* ptr, uint16_t val) {
    val = htons(val);
    memcpy(ptr, &val, 2);
}

/** @brief Read a 16-bit value from network byte order */
static inline uint16_t read_u16(const uint8_t* ptr) {
    uint16_t val;
    memcpy(&val, ptr, 2);
    return ntohs(val);
}

/** @brief Read a 32-bit value from network byte order */
static inline uint32_t read_u32(const uint8_t* ptr) {
    uint32_t val;
    memcpy(&val, ptr, 4);
    return ntohl(val);
}

int dns_parser_parse_name_impl(
    const uint8_t* packet,
    int offset,
    int max_len,
    uint32_t* out_hash,
    uint8_t* dest,
    int dest_max,
    int* out_consumed
) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    int current_offset = offset;
    int jumped = 0;
    int count = 0;
    int consumed_len = 0;
    int written = 0;

    while (count++ < MAX_DNS_LABEL_ITERATIONS) {
        if (current_offset >= max_len)
            return -1;
        unsigned char len = packet[current_offset];

        if (len == 0) {
            if (!jumped)
                consumed_len++;
            if (dest) {
                if (written >= dest_max)
                    return -1;
                dest[written] = 0;
            }
            written++;
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

        if (dest) {
            if (written + 1 + len > dest_max)
                return -1;
            dest[written] = len;
            memcpy(dest + written + 1, packet + current_offset + 1, len);
        }
        written += (1 + len);

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

    if (count > MAX_DNS_LABEL_ITERATIONS)
        return -1;
    if (out_hash)
        *out_hash = hash;
    if (out_consumed)
        *out_consumed = consumed_len;
    return written;
}

int dns_parser_calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    int consumed = 0;
    int ret = dns_parser_parse_name_impl(packet, offset, max_len, out_hash, NULL, 0, &consumed);
    if (ret < 0)
        return -1;
    return consumed;
}

static int calculate_hash_strict(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    return dns_parser_calculate_hash_strict_impl(packet, offset, max_len, out_hash);
}

int dns_parser_flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    return dns_parser_parse_name_impl(packet, offset, max_len, NULL, dest, dest_max, NULL);
}

/** @brief Wrapper for dns_parser_flatten_name_impl */
static int flatten_name(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    return dns_parser_flatten_name_impl(packet, offset, max_len, dest, dest_max);
}

/**
 * @brief Skip a DNS name in wire format, returning bytes consumed.
 * @param packet DNS packet data.
 * @param offset Offset to start of DNS name.
 * @param max_len Maximum bytes to read.
 * @return Bytes consumed, or negative on error.
 * @note Re-uses calculate_hash_strict with a throwaway hash.
 */
static int skip_name(const uint8_t* packet, int offset, int max_len) {
    uint32_t unused_hash;
    return calculate_hash_strict(packet, offset, max_len, &unused_hash);
}

struct ecs_parse_result {
    uint8_t present;
    uint8_t scope_prefix;
    uint8_t source_prefix;
    uint8_t family;
    uint32_t addr_v4;
};

#if SHINKU_ECS_ENABLED
static int parse_ecs_option_ipv4(const uint8_t* pkt, int offset, int max_len, int rdlen, struct ecs_parse_result* out) {
    if (!out)
        return -1;

    int end = offset + rdlen;
    if (end < offset || end > max_len)
        return -1;

    while (offset + 4 <= end) {
        uint16_t opt_code = read_u16(pkt + offset);
        uint16_t opt_len = read_u16(pkt + offset + 2);
        offset += 4;

        if (offset + opt_len > end)
            return -1;

        if (opt_code == EDNS0_OPT_CODE_ECS && opt_len >= 4) {
            uint16_t family = read_u16(pkt + offset);
            uint8_t src_prefix = pkt[offset + 2];
            uint8_t scope_prefix = pkt[offset + 3];

            if (family != 1)
                return -1;
            if (src_prefix > 32)
                return -1;
            if (scope_prefix > 32)
                return -1;
            if (scope_prefix > src_prefix)
                return -1;

            int addr_bytes = (src_prefix + 7) / 8;
            if (opt_len < 4 + addr_bytes)
                return -1;

            uint32_t addr = 0;
            for (int i = 0; i < addr_bytes && i < 4; i++) {
                addr |= ((uint32_t)pkt[offset + 4 + i]) << (24 - (8 * i));
            }

            uint32_t mask = src_prefix == 0 ? 0 : (0xffffffffu << (32 - src_prefix));
            addr &= mask;

            out->present = 1;
            out->scope_prefix = scope_prefix;
            out->source_prefix = src_prefix;
            out->family = 1;
            out->addr_v4 = htonl(addr);
            return 1;
        }

        offset += opt_len;
    }

    return 0;
}

#else

static inline int
parse_ecs_option_ipv4(const uint8_t* pkt, int offset, int max_len, int rdlen, struct ecs_parse_result* out) {
    (void)pkt;
    (void)offset;
    (void)max_len;
    (void)rdlen;
    if (out)
        memset(out, 0, sizeof(*out));
    return 0;
}

#endif

static int read_soa_negative_ttl(const uint8_t* pkt_data, int rdata_off, int pkt_len, uint32_t* out_ttl) {
    int mname = skip_name(pkt_data, rdata_off, pkt_len);
    if (mname < 0)
        return -1;
    int rname_off = rdata_off + mname;
    int rname = skip_name(pkt_data, rname_off, pkt_len);
    if (rname < 0)
        return -1;

    int numeric_off = rname_off + rname;
    if (numeric_off + 20 > pkt_len)
        return -1;

    *out_ttl = read_u32(pkt_data + numeric_off + 16);
    return 0;
}

static struct negative_cache_info parse_negative_cache_info(
    struct dns_parser_runtime* runtime,
    const uint8_t* pkt_data,
    uint32_t pkt_len,
    uint16_t flags,
    uint16_t qdcount,
    uint16_t ancount,
    uint16_t nscount
) {
    struct negative_cache_info info = { 0 };

    uint16_t rcode = (uint16_t)(flags & DNS_RCODE_MASK);
    int is_nxdomain = (rcode == DNS_RCODE_NXDOMAIN);
    int is_nodata = (rcode == DNS_RCODE_NOERROR && ancount == 0);

    if (!is_nxdomain && !is_nodata)
        return info;

    uint32_t read_offset = sizeof(struct dns_hdr);
    for (uint16_t i = 0; i < qdcount; i++) {
        int skip = skip_name(pkt_data, (int)read_offset, (int)pkt_len);
        if (skip < 0)
            return info;
        read_offset += (uint32_t)skip;
        if (read_offset + 4 > pkt_len)
            return info;
        read_offset += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        int skip = skip_name(pkt_data, (int)read_offset, (int)pkt_len);
        if (skip < 0)
            return info;
        read_offset += (uint32_t)skip;
        if (read_offset + 10 > pkt_len)
            return info;
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10;
        if (read_offset + rdlen > pkt_len)
            return info;
        read_offset += rdlen;
    }

    int found_soa = 0;
    uint32_t best_soa_ttl = UINT32_MAX;
    for (uint16_t i = 0; i < nscount; i++) {
        int skip = skip_name(pkt_data, (int)read_offset, (int)pkt_len);
        if (skip < 0)
            return info;
        read_offset += (uint32_t)skip;
        if (read_offset + 10 > pkt_len)
            return info;

        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint32_t rr_ttl = read_u32(pkt_data + read_offset + 4);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        int rdata_off = (int)read_offset + 10;
        read_offset += 10;

        if (read_offset + rdlen > pkt_len)
            return info;

        if (rtype == DNS_TYPE_SOA) {
            uint32_t minimum = 0;
            if (read_soa_negative_ttl(pkt_data, rdata_off, (int)pkt_len, &minimum) == 0) {
                uint32_t candidate = rr_ttl < minimum ? rr_ttl : minimum;
                if (candidate < best_soa_ttl)
                    best_soa_ttl = candidate;
                found_soa = 1;
            }
        }
        read_offset += rdlen;
    }

    if (!found_soa) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_NEGATIVE_NO_SOA
        );
        obs_metrics_count_negative_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            is_nxdomain ? OBS_NEGATIVE_NXDOMAIN : OBS_NEGATIVE_NODATA
        );
        return info;
    }

    uint32_t ttl = clamp_negative_ttl(best_soa_ttl);
    if (ttl == 0 || ttl == UINT32_MAX) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_NEGATIVE_BAD_POLICY
        );
        obs_metrics_count_negative_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            is_nxdomain ? OBS_NEGATIVE_NXDOMAIN : OBS_NEGATIVE_NODATA
        );
        return info;
    }

    info.valid = 1;
    info.ttl = ttl;
    info.type = is_nxdomain ? OBS_NEGATIVE_NXDOMAIN : OBS_NEGATIVE_NODATA;
    info.flags = CACHE_VALUE_FLAG_NEGATIVE;
    if (is_nxdomain)
        info.flags |= CACHE_VALUE_FLAG_NXDOMAIN;
    return info;
}

int dns_parser_cleanup_expired_entries(struct cache_context* cache_ctx) {
    return dns_cache_cleanup_expired_entries(cache_ctx);
}

int dns_parser_handle_event(void* ctx, void* data, [[maybe_unused]] size_t len) {
    struct dns_parser_context* parser_ctx = ctx;
    struct cache_context* cache_ctx = parser_ctx ? parser_ctx->cache : NULL;
    struct dns_parser_runtime* runtime = parser_ctx ? parser_ctx->runtime : NULL;
    struct dns_event* e = data;
    uint32_t pkt_len = e->len;
    uint8_t* pkt_data = e->payload;

    if (pkt_len < sizeof(struct dns_hdr)) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_MALFORMED_RR
        );
        return 0;
    }

    struct dns_hdr* dns = (struct dns_hdr*)pkt_data;
    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t nscount = ntohs(dns->nscount);
    uint16_t flags = ntohs(dns->flags);

    struct negative_cache_info neg_info =
        parse_negative_cache_info(runtime, pkt_data, pkt_len, flags, qdcount, ancount, nscount);

    uint8_t is_response = (flags >> 15) & 0x1;
    if (!is_response) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_NOT_RESPONSE
        );
        return 0;
    }
    if (qdcount != 1) {
        obs_metrics_count_parser_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL, OBS_REJECT_BAD_QDCOUNT);
        return 0;
    }
    if ((flags & DNS_RCODE_MASK) != 0 && !neg_info.valid) {
        obs_metrics_count_parser_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL, OBS_REJECT_RCODE);
        return 0;
    }
    if (ancount == 0 && !neg_info.valid) {
        obs_metrics_count_parser_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL, OBS_REJECT_NO_ANSWER);
        return 0;
    }

    uint32_t name_hash = 0;
    uint32_t read_offset = sizeof(struct dns_hdr);
    int qname_len_packet = calculate_hash_strict(pkt_data, read_offset, pkt_len, &name_hash);

    if (qname_len_packet < 0) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_MALFORMED_NAME
        );
        return 0;
    }

    int q_end = read_offset + qname_len_packet;
    if ((uint32_t)q_end + 4 > pkt_len) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_MALFORMED_QUESTION
        );
        return 0;
    }
    uint16_t qtype = read_u16(pkt_data + q_end);
    uint16_t qclass = read_u16(pkt_data + q_end + 2);

    if (qtype == DNS_TYPE_AAAA) {
        obs_metrics_count_parser_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_REJECT_IPV6_IGNORED
        );
        return 0;
    }

    if (flags & DNS_FLAG_TC) {
        struct cache_key tc_key = { CACHE_KEY_CORE_AND_ECS_INIT_DESIG(name_hash, qtype, qclass, 0, 0, 0) };

        dns_cache_store_raw_response(cache_ctx, runtime, &tc_key, pkt_data, (int)pkt_len, NEGATIVE_TTL_MIN, 0);
        return 0;
    }

    uint8_t* flat_buf = dns_parser_flat_buf_tls;
    const int flat_capacity = DNS_PARSER_FLAT_BUF_SIZE;
    int flat_offset = 0;

    memcpy(flat_buf, dns, sizeof(*dns));
    struct dns_hdr* flat_hdr = (struct dns_hdr*)flat_buf;
    flat_hdr->arcount = 0;
    flat_hdr->nscount = 0;
    flat_offset += sizeof(struct dns_hdr);

    int w_len = flatten_name(pkt_data, read_offset, pkt_len, flat_buf + flat_offset, flat_capacity - flat_offset);
    if (w_len < 0)
        return 0;
    flat_offset += w_len;

    write_u16(flat_buf + flat_offset, qtype);
    write_u16(flat_buf + flat_offset + 2, qclass);
    flat_offset += 4;

    read_offset = q_end + 4;

    uint32_t min_ttl = neg_info.valid ? neg_info.ttl : UINT32_MAX;
    int has_terminal_rr = 0;
    int has_cname_rr = 0;
    int has_ipv6_rr = 0;

    for (int i = 0; i < ancount; i++) {
        int name_skip = 0;
        w_len = dns_parser_parse_name_impl(
            pkt_data,
            read_offset,
            pkt_len,
            NULL,
            flat_buf + flat_offset,
            flat_capacity - flat_offset,
            &name_skip
        );
        if (w_len < 0) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_NAME
            );
            return 0;
        }
        read_offset += name_skip;
        flat_offset += w_len;

        if (read_offset + 10 > pkt_len) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }

        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint32_t ttl = read_u32(pkt_data + read_offset + 4);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);

        if (ttl < min_ttl)
            min_ttl = ttl;

        if (flat_offset + 10 > flat_capacity) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }
        memcpy(flat_buf + flat_offset, pkt_data + read_offset, 10);
        flat_offset += 10;
        read_offset += 10;

        if (read_offset + rdlen > pkt_len) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }

        if (rtype == DNS_TYPE_A || rtype == DNS_TYPE_AAAA) {
            if (rtype == DNS_TYPE_A)
                has_terminal_rr = 1;
            if (rtype == DNS_TYPE_AAAA)
                has_ipv6_rr = 1;
            if (flat_offset + rdlen > flat_capacity) {
                obs_metrics_count_parser_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL,
                    OBS_REJECT_MALFORMED_RR
                );
                return 0;
            }
            memcpy(flat_buf + flat_offset, pkt_data + read_offset, rdlen);
            flat_offset += rdlen;
        } else if (rtype == DNS_TYPE_CNAME) {
            has_cname_rr = 1;
            int cname_len = flatten_name(pkt_data, read_offset, pkt_len, NULL, 0);
            if (cname_len < 0) {
                obs_metrics_count_parser_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL,
                    OBS_REJECT_MALFORMED_NAME
                );
                return 0;
            }
            if ((uint16_t)cname_len != rdlen) {
                obs_metrics_count_parser_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL,
                    OBS_REJECT_MALFORMED_NAME
                );
                return 0;
            }
            if (flat_offset + rdlen > flat_capacity) {
                obs_metrics_count_parser_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL,
                    OBS_REJECT_MALFORMED_RR
                );
                return 0;
            }
            memcpy(flat_buf + flat_offset, pkt_data + read_offset, rdlen);
            flat_offset += rdlen;
        } else {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_UNSUPPORTED_RTYPE
            );
            return 0;
        }
        read_offset += rdlen;
    }

    if (!neg_info.valid && qtype == DNS_TYPE_A && !has_terminal_rr) {
        enum obs_parser_reject_reason reason = OBS_REJECT_UNSUPPORTED_RTYPE;
        if (has_cname_rr && has_ipv6_rr)
            reason = OBS_REJECT_CNAME_IPV6_ONLY_TERMINAL;
        else if (has_cname_rr)
            reason = OBS_REJECT_CNAME_NO_TERMINAL_A;
        else if (has_ipv6_rr)
            reason = OBS_REJECT_IPV6_IGNORED;

        obs_metrics_count_parser_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL, reason);
        return 0;
    }

    /* Skip Authority Section */
    for (int i = 0; i < nscount; i++) {
        int name_skip = skip_name(pkt_data, read_offset, pkt_len);
        if (name_skip < 0) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_NAME
            );
            return 0;
        }
        read_offset += name_skip;
        if (read_offset + 10 > pkt_len) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10 + rdlen;
    }

    /* Scan Additional Section for OPT RR / ECS */
    uint8_t ecs_scope = 0;
    struct ecs_parse_result ecs = { 0 };
    uint16_t arcount = ntohs(dns->arcount);
    for (int i = 0; i < arcount; i++) {
        int name_skip = skip_name(pkt_data, read_offset, pkt_len);
        if (name_skip < 0) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_NAME
            );
            return 0;
        }
        read_offset += name_skip;
        if (read_offset + 10 > pkt_len) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }

        uint16_t rtype = read_u16(pkt_data + read_offset);
        uint16_t rdlen = read_u16(pkt_data + read_offset + 8);
        read_offset += 10;

        if (rtype == DNS_TYPE_OPT) {
            int ecs_parse = parse_ecs_option_ipv4(pkt_data, read_offset, pkt_len, rdlen, &ecs);
            if (ecs_parse < 0) {
                obs_metrics_count_parser_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL,
                    OBS_REJECT_BAD_ECS
                );
                return 0;
            }

            if (ecs_parse > 0)
                ecs_scope = ecs.scope_prefix;
        }

        if (read_offset + rdlen > pkt_len) {
            obs_metrics_count_parser_reject(
                runtime && runtime->obs ? runtime->obs->metrics : NULL,
                OBS_REJECT_MALFORMED_RR
            );
            return 0;
        }
        read_offset += rdlen;
    }

    if (min_ttl == 0 || min_ttl == UINT32_MAX) {
        obs_metrics_count_parser_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL, OBS_REJECT_BAD_TTL);
        return 0;
    }

    struct cache_key key = { CACHE_KEY_CORE_AND_ECS_INIT_DESIG(
        name_hash,
        qtype,
        qclass,
        (ecs_scope > 0 ? ecs.addr_v4 : 0),
        (ecs_scope > 0 ? ecs.source_prefix : 0),
        (ecs_scope > 0 ? ecs.family : 0)
    ) };

    if (neg_info.valid) {
        obs_metrics_count_negative_accept(runtime && runtime->obs ? runtime->obs->metrics : NULL, neg_info.type);
        dns_cache_store_response_with_flags(
            cache_ctx,
            runtime,
            &key,
            flat_buf,
            flat_offset,
            min_ttl,
            ecs_scope,
            neg_info.flags
        );
    } else {
        uint8_t* store_buf = flat_buf;
        int store_len = flat_offset;
        if (has_cname_rr && pkt_len <= ARENA_ENTRY_SIZE) {
            store_buf = pkt_data;
            store_len = (int)pkt_len;
        }
        dns_cache_store_response(cache_ctx, runtime, &key, store_buf, store_len, min_ttl, ecs_scope);
    }

    return 0;
}

int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash) {
    return dns_parser_calculate_hash_strict_impl(packet, offset, max_len, out_hash);
}

int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max) {
    return dns_parser_flatten_name_impl(packet, offset, max_len, dest, dest_max);
}
