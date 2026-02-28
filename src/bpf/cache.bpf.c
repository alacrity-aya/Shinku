#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "types.h"
#include "core/hash.h"
#include "xdp_parser.h"
#include "bpf/arena/bpf_arena_common.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u16 read_u16_unaligned(void* ptr) {
    __u8* b = (__u8*)ptr;
    return (b[0] << 8) | b[1];
}

/* Incremental checksum update (RFC 1624).
 * Updates a 16-bit one's complement checksum when a single 16-bit word changes.
 * All values in network byte order. */
static __always_inline void csum_replace2(__sum16 *csum, __be16 old_val, __be16 new_val) {
    __u32 sum;
    sum  = ~((__u16)*csum) & 0xffff;
    sum += ~((__u16)old_val) & 0xffff;
    sum += (__u16)new_val;
    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
    *csum = (__sum16)(~sum & 0xffff);
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_PKT);
} rb_pkt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CACHE_MAP_MAX_ENTRIES);
    __type(key, struct cache_key);
    __type(value, struct cache_value);
} cache_map SEC(".maps");

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
    void* data     = (void*)(long)ctx->data;
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
    __u16 flags   = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);

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
    __u16 qtype  = read_u16_unaligned(cursor);
    __u16 qclass = read_u16_unaligned(cursor + 2);

    /* ── Phase 2: Cache lookup ── */
    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    bpf_debug("[XDP] Key: Hash=0x%x Type=%d Class=%d", key.name_hash, key.qtype, key.qclass);

    struct cache_value *val = bpf_map_lookup_elem(&cache_map, &key);
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
    __u32 l2_len = (__u32)((void*)ip - data);  /* ETH + any VLANs */

    /* Bound hints for the verifier */
    if (l2_len > 64 || ip_hdr_len > 60)
        return XDP_PASS;

    __u32 hdr_total    = l2_len + ip_hdr_len + sizeof(struct udphdr);
    __u32 current_len  = (__u32)(data_end - data);
    __u32 new_pkt_len  = hdr_total + cached_len;
    int   tail_diff    = (int)new_pkt_len - (int)current_len;

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
    data     = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;

    /* Force tight 64-bit bounds via AND masks (not conditional checks).
     * l2_len: ETH(14) + up to 2 VLAN tags(8) = max 22, mask with 0x3F (63).
     * ip_hdr_len: 20..60, mask with 0x3F (63).
     * cached_len: 1..512, mask with 0x3FF (1023) — generous to keep 512 valid. */
    l2_len     &= 0x3F;
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

    /* ── Phase 5: Copy cached DNS response from arena ── */
    struct cache_entry __arena *entry = &cache_entries[arena_idx];

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < ARENA_ENTRY_SIZE; i++) {
        if (i >= cached_len)
            break;
        if (dns_start + i + 1 > (__u8*)data_end)
            break;
        dns_start[i] = entry->pkt[i];
    }

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
    udp->dest   = tmp_port;

    /* Update UDP length; zero checksum is valid for IPv4 (RFC 768) */
    udp->len   = bpf_htons((__u16)(sizeof(struct udphdr) + cached_len));
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
