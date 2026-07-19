// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file cache.bpf.c
 * @brief Main XDP/TC BPF program for DNS caching.
 *
 * This file contains the core packet processing logic:
 *   - XDP program: Handles DNS query lookup and cache serving
 *   - TC program: Captures DNS responses for userspace processing
 *
 * Packet flow:
 *   1. XDP receives DNS queries on port 53
 *   2. Query name is hashed and looked up in cache_map
 *   3. On hit: Response is constructed and transmitted (XDP_TX)
 *   4. On miss: Packet passes through to upstream resolver
 *   5. TC captures responses and sends to userspace via ring buffer
 *
 * Memory model:
 *   - cache_map: BPF hashmap for cache metadata lookup
 *   - arena: Shared BPF/userspace memory for DNS packet storage
 *   - rb_pkt: Ring buffer for DNS response capture
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf/arena/bpf_arena_common.h"
#include "bpf_log.h"
#include "core/hash.h"
#include "types.h"
#include "xdp_parser.h"

char LICENSE[] SEC("license") = "GPL";

/** @brief Read a potentially unaligned 16-bit value (network byte order) */
static __always_inline __u16 read_u16_unaligned(void* ptr) {
    __u8* b = (__u8*)ptr;
    return (b[0] << 8) | b[1];
}

/**
 * @brief Generate IPv4 prefix mask for subnet extraction.
 * @param prefix Prefix length (0-32).
 * @return Mask value with prefix bits set to 1.
 */
static __always_inline __u32 prefix_mask_v4(__u8 prefix) {
    if (prefix == 0)
        return 0;
    if (prefix >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - prefix);
}

enum {
    OPT_RR_HDR_LEN = 11,
    OPT_RR_TYPE_OFF = 1,
    OPT_RR_RDLEN_OFF = 9,
    ECS_OPT_CODE_OFF = 11,
    ECS_OPT_LEN_OFF = 13,
    ECS_FAMILY_OFF = 15,
    ECS_SRC_PREFIX_OFF = 17,
    ECS_ADDR_OFF = 19,
    ECS_MAX_SCAN_END_OFF = 23,
    ECS_OPT_MIN_LEN = 4,
    ECS_OPT_MAX_LEN = 8,
    ECS_RDLEN_MIN = 8,
};

#if SHINKU_ECS_ENABLED
static __always_inline void
parse_query_ecs_v4_single_opt(__u8* p, __u8* data_end, __u32* ecs_addr_v4, __u8* ecs_prefix, __u8* ecs_family) {
    if (!p || !ecs_addr_v4 || !ecs_prefix || !ecs_family)
        return;

    if (p + OPT_RR_HDR_LEN > data_end)
        return;

    if (p[0] != 0)
        return;

    __u16 opt_rr_type = ((__u16)p[OPT_RR_TYPE_OFF] << 8) | p[OPT_RR_TYPE_OFF + 1];
    if (opt_rr_type != DNS_TYPE_OPT)
        return;

    __u16 rdlen = ((__u16)p[OPT_RR_RDLEN_OFF] << 8) | p[OPT_RR_RDLEN_OFF + 1];
    if (rdlen < ECS_RDLEN_MIN)
        return;

    if (p + ECS_MAX_SCAN_END_OFF > data_end)
        return;

    __u16 opt_code = ((__u16)p[ECS_OPT_CODE_OFF] << 8) | p[ECS_OPT_CODE_OFF + 1];
    if (opt_code != EDNS0_OPT_CODE_ECS)
        return;

    __u16 opt_len = ((__u16)p[ECS_OPT_LEN_OFF] << 8) | p[ECS_OPT_LEN_OFF + 1];
    __u16 family = ((__u16)p[ECS_FAMILY_OFF] << 8) | p[ECS_FAMILY_OFF + 1];
    __u8 src_prefix = p[ECS_SRC_PREFIX_OFF];

    if (family != 1 || src_prefix > 32)
        return;

    __u8 addr_bytes = (src_prefix + 7) / 8;
    if (opt_len != (__u16)(ECS_OPT_MIN_LEN + addr_bytes) || opt_len > ECS_OPT_MAX_LEN)
        return;

    if (rdlen < (__u16)(opt_len + ECS_OPT_MIN_LEN))
        return;

    __u32 addr = 0;
    if (addr_bytes > 0)
        addr |= ((__u32)p[ECS_ADDR_OFF]) << 24;
    if (addr_bytes > 1)
        addr |= ((__u32)p[ECS_ADDR_OFF + 1]) << 16;
    if (addr_bytes > 2)
        addr |= ((__u32)p[ECS_ADDR_OFF + 2]) << 8;
    if (addr_bytes > 3)
        addr |= (__u32)p[ECS_ADDR_OFF + 3];

    addr &= prefix_mask_v4(src_prefix);
    *ecs_addr_v4 = bpf_htonl(addr);
    *ecs_prefix = src_prefix;
    *ecs_family = src_prefix > 0 ? 1 : 0;
}
#else
static __always_inline void
parse_query_ecs_v4_single_opt(__u8* p, __u8* data_end, __u32* ecs_addr_v4, __u8* ecs_prefix, __u8* ecs_family) {
    (void)p;
    (void)data_end;
    if (ecs_addr_v4)
        *ecs_addr_v4 = 0;
    if (ecs_prefix)
        *ecs_prefix = 0;
    if (ecs_family)
        *ecs_family = 0;
}
#endif

/* Incremental checksum update (RFC 1624).
 * Updates a 16-bit one's complement checksum when a single 16-bit word changes.
 * All values in network byte order. */
static __always_inline void csum_replace2(__sum16* csum, __be16 old_val, __be16 new_val) {
    __u32 sum;
    sum = ~((__u16)*csum) & 0xffff;
    sum += ~((__u16)old_val) & 0xffff;
    sum += (__u16)new_val;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    *csum = (__sum16)(~sum & 0xffff);
}

/** @brief Ring buffer for sending captured DNS responses to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_PKT);
} rb_pkt SEC(".maps");

/** @brief Hash map for cache metadata (key: cache_key, value: cache_value) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CACHE_MAP_MAX_ENTRIES);
    __type(key, struct cache_key);
    __type(value, struct cache_value);
} cache_map SEC(".maps");

/** @brief Shared arena for DNS packet storage (BPF/userspace mmap) */
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, ARENA_DEFAULT_PAGES);
    __uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
/* Arena-resident cache entry storage — shared with userspace via mmap.
 * Userspace writes entries here; XDP reads them for cache hits. */
struct cache_entry __arena cache_entries[CACHE_MAP_MAX_ENTRIES];
/* Next free slot index — managed by userspace, readable by BPF. */
__u32 __arena next_entry_idx;
#else
struct cache_entry cache_entries[1] SEC(".addr_space.1");
__u32 next_entry_idx SEC(".addr_space.1");
#endif

SEC("xdp")
int xdp_rx(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    bpf_debug("[XDP] RX pkt len=%lu", (__u32)(data_end - data));

    /* ── Phase 1: Inline ETH → VLAN → IP → UDP → DNS parsing ──
     * We inline rather than calling parse_dns_header() because
     * the hot-patch path needs eth/ip/udp pointers. */

    /* L2: Ethernet */
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    void* next_hdr = (void*)(eth + 1);

    /* L2.5: Skip VLAN tags (Q-in-Q support) */
    skip_vlan_tags(&proto, &next_hdr, data_end);

    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* L3: IPv4 */
    struct iphdr* ip = next_hdr;
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void*)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    /* L4: UDP */
    struct udphdr* udp = (void*)ip + ip_hdr_len;
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(DNS_PORT))
        return XDP_PASS;

    /* L7: DNS header */
    struct dns_hdr* dns = (void*)(udp + 1);
    if ((void*)(dns + 1) > data_end)
        return XDP_PASS;

    /* Save query transaction ID (network byte order) for patching later */
    __be16 query_id = dns->id;
    __u16 flags = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);
    __u16 arcount = bpf_ntohs(dns->arcount);

    /* Only process queries (QR=0) with exactly 1 question */
    if ((flags & DNS_FLAG_QR) || qdcount != 1)
        return XDP_PASS;

    bpf_info("[XDP] DNS Query: ID=0x%04x Flags=0x%04x", bpf_ntohs(query_id), flags);

    /* Hash the QNAME */
    void* cursor = (void*)(dns + 1);
    __u32 name_hash = 0;
    if (calculate_dns_name_hash(&cursor, data_end, &name_hash) < 0) {
        bpf_warn("[XDP] Hash failed: ID=0x%04x (truncated/invalid)", bpf_ntohs(query_id));
        return XDP_PASS;
    }

    /* Read QTYPE and QCLASS (host byte order) */
    if (cursor + 4 > data_end)
        return XDP_PASS;
    __u16 qtype = read_u16_unaligned(cursor);
    __u16 qclass = read_u16_unaligned(cursor + 2);

    __u32 ecs_addr_v4 = 0;
    __u8 ecs_prefix = 0;
    __u8 ecs_family = 0;
    void* addl = cursor + 4;
    if (arcount == 1)
        parse_query_ecs_v4_single_opt((__u8*)addl, (__u8*)data_end, &ecs_addr_v4, &ecs_prefix, &ecs_family);

    /* ── Phase 2: Cache lookup ── */
    struct cache_key key = {
        CACHE_KEY_CORE_AND_ECS_INIT_DESIG(name_hash, qtype, qclass, ecs_addr_v4, ecs_prefix, ecs_family)
    };

    bpf_debug("[XDP] Key: Hash=0x%x Type=%d Class=%d", key.name_hash, key.qtype, key.qclass);

    struct cache_value* val = bpf_map_lookup_elem(&cache_map, &key);
    if (!val)
        return XDP_PASS;

    /* TTL check: expired entries fall through to upstream */
    __u64 now = bpf_ktime_get_ns();
    if (now >= val->expire_ts) {
        bpf_debug("[XDP] Cache expired: Hash=0x%x", name_hash);
        return XDP_PASS;
    }

    /* Validate arena index and packet length */
    __u32 arena_idx = val->arena_idx;
    if (arena_idx >= CACHE_MAP_MAX_ENTRIES)
        return XDP_PASS;

    __u16 cached_len = val->pkt_len;
    if (cached_len == 0 || cached_len > ARENA_ENTRY_SIZE)
        return XDP_PASS;

    /* ── Phase 3: Resize packet via bpf_xdp_adjust_tail ── */
    __u32 l2_len = (__u32)((void*)ip - data); /* ETH + any VLANs */

    /* Bound hints for the verifier */
    if (l2_len > 64 || ip_hdr_len > 60)
        return XDP_PASS;

    __u32 hdr_total = l2_len + ip_hdr_len + sizeof(struct udphdr);
    __u32 current_len = (__u32)(data_end - data);
    __u32 new_pkt_len = hdr_total + cached_len;
    int tail_diff = (int)new_pkt_len - (int)current_len;

    if (bpf_xdp_adjust_tail(ctx, tail_diff)) {
        bpf_warn("[XDP] adjust_tail failed: diff=%d", tail_diff);
        return XDP_PASS;
    }

    /* ── Phase 4: Re-derive ALL pointers (mandatory after adjust_tail) ──
     * After bpf_xdp_adjust_tail(), the verifier invalidates all packet
     * pointer state. We must:
     *   1. Re-read data/data_end from ctx
     *   2. Re-narrow ALL scalar offsets with bitwise AND masks.
     *      Conditional checks (if x > N) only narrow 32-bit sub-register
     *      bounds when the variable is __u32. AND masks narrow BOTH
     *      32-bit and 64-bit bounds, which is required for pkt pointer
     *      arithmetic.
     */
    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;

    /* Force tight 64-bit bounds via AND masks (not conditional checks).
     * l2_len: ETH(14) + up to 2 VLAN tags(8) = max 22, mask with 0x3F (63).
     * ip_hdr_len: 20..60, mask with 0x3F (63).
     * cached_len: 1..512, mask with 0x3FF (1023) — generous to keep 512 valid. */
    l2_len &= 0x3F;
    ip_hdr_len &= 0x3F;
    cached_len &= 0x3FF;
    if (cached_len == 0)
        return XDP_PASS;

    eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    ip = (struct iphdr*)(data + l2_len);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if ((void*)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    udp = (struct udphdr*)((void*)ip + ip_hdr_len);
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;

    __u8* dns_start = (__u8*)(udp + 1);
    if (dns_start + cached_len > (__u8*)data_end)
        return XDP_PASS;

    /* ── Phase 5: Seqlock read + generation check + arena copy (8-byte wide) ── */
    struct cache_entry __arena* entry = &cache_entries[arena_idx];

    /* Generation check: detect slot reuse between cache_map lookup and arena read */
    __u32 entry_gen = READ_ONCE(entry->gen);
    if (entry_gen != val->gen) {
        bpf_debug("[XDP] Gen mismatch: entry=%u val=%u Hash=0x%x", entry_gen, val->gen, name_hash);
        return XDP_PASS;
    }

    /* Seqlock read barrier: seq must be even (no write in progress) */
    __u32 seq1 = READ_ONCE(entry->seq);
    if (seq1 & 1)
        return XDP_PASS;

    /* 8-byte wide copies: reduces iteration count by ~8x */
    __u32 copy_words = cached_len >> 3; /* full 8-byte chunks */
    __u32 copy_rem = cached_len & 0x7;  /* remaining bytes */

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < ARENA_ENTRY_SIZE / 8; i++) {
        if (i >= copy_words)
            break;
        __u32 off = i << 3;
        if (dns_start + off + 8 > (__u8*)data_end)
            break;
        *(__u64*)(dns_start + off) = *(__u64*)(entry->pkt + off);
    }

    /* Copy remaining 0-7 bytes */
    __u32 rem_start = copy_words << 3;
#pragma clang loop unroll(enable)
    for (__u32 i = 0; i < 7; i++) {
        if (i >= copy_rem)
            break;
        __u32 off = rem_start + i;
        if (dns_start + off + 1 > (__u8*)data_end)
            break;
        dns_start[off] = entry->pkt[off];
    }

    /* Seqlock validation: seq must not have changed during copy */
    __u32 seq2 = READ_ONCE(entry->seq);
    if (seq1 != seq2)
        return XDP_PASS;

    /* ── Phase 6: Patch transaction ID to match original query ── */
    struct dns_hdr* resp = (struct dns_hdr*)dns_start;
    if ((void*)(resp + 1) > data_end)
        return XDP_PASS;
    resp->id = query_id;

    /* ── Phase 7: Swap L2/L3/L4 headers + fix checksums ── */

    /* Swap MAC addresses */
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    /* Swap IP addresses (checksum-neutral: addition is commutative) */
    __be32 tmp_addr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_addr;

    /* Update IP total_len + incremental checksum */
    __be16 old_tot_len = ip->tot_len;
    __be16 new_tot_len = bpf_htons((__u16)(ip_hdr_len + sizeof(struct udphdr) + cached_len));
    ip->tot_len = new_tot_len;
    csum_replace2(&ip->check, old_tot_len, new_tot_len);

    /* Swap UDP ports */
    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    /* Update UDP length; zero checksum is valid for IPv4 (RFC 768) */
    udp->len = bpf_htons((__u16)(sizeof(struct udphdr) + cached_len));
    udp->check = 0;

    bpf_info("[XDP] Cache HIT -> XDP_TX: Hash=0x%x len=%d", name_hash, cached_len);

    return XDP_TX;
}

// Capture DNS responses in TC and send to user space via ring buffer
SEC("tc")
int tc_tx(struct __sk_buff* skb) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = eth->h_proto;
    void* next_hdr = (void*)(eth + 1);

    // Skip VLAN tags (Q-in-Q support)
    skip_vlan_tags(&proto, &next_hdr, data_end);

    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr* ip = next_hdr;
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_len = ip->ihl * 4;
    struct udphdr* udp = (void*)ip + ip_len;
    if ((void*)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (udp->source != bpf_htons(DNS_PORT)) {
        return TC_ACT_OK;
    }

    /* Compute offset of DNS payload within the skb for bpf_skb_load_bytes.
     * dns_offset = ETH header + IP header + UDP header */
    __u32 dns_offset = (__u32)((void*)(udp + 1) - (void*)(unsigned long)skb->data);

    /* Compute DNS payload length from IP total length to handle
     * any padding added by the network layer. */
    __u32 ip_total = bpf_ntohs(ip->tot_len);
    __u32 dns_len;
    if (ip_total > ip_len + sizeof(struct udphdr))
        dns_len = ip_total - ip_len - sizeof(struct udphdr);
    else
        return TC_ACT_OK;

    /* Cap to ARENA_ENTRY_SIZE (512) - that's the max we can store in the arena cache. */
    if (dns_len < 1)
        return TC_ACT_OK;
    if (dns_len > ARENA_ENTRY_SIZE)
        dns_len = ARENA_ENTRY_SIZE;

    struct dns_event* e = bpf_ringbuf_reserve(&rb_pkt, sizeof(*e) + ARENA_ENTRY_SIZE, 0);
    if (unlikely(!e)) {
        bpf_warn("[TC] RingBuf full, dropped DNS Resp (len=%u)", skb->len);
        return TC_ACT_OK;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->len = dns_len;

    /* Use bpf_skb_load_bytes with bounded variable length.
     * dns_len is proven in [1, ARENA_ENTRY_SIZE] by the checks above. */
    long ret = bpf_skb_load_bytes(skb, dns_offset, e->payload, dns_len);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        bpf_warn("[TC] skb_load_bytes failed: off=%u len=%u ret=%ld", dns_offset, dns_len, ret);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(e, 0);
    bpf_info("[TC] Captured DNS Resp: len=%u saved=%u", skb->len, dns_len);

    return TC_ACT_OK;
}
