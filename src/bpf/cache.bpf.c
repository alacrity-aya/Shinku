#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "types.h"
#include "core/hash.h"
#include "xdp_parser.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u16 read_u16_unaligned(void* ptr) {
    __u8* b = (__u8*)ptr;
    return (b[0] << 8) | b[1];
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE_PKT);
} rb_pkt SEC(".maps");

SEC("xdp")
int xdp_rx(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = NULL;

    bpf_debug("[XDP] RX pkt len=%lu", (__u32)(data_end - (void*)(long)ctx->data));

    struct dns_hdr* dns = parse_dns_header(ctx, &cursor, data_end);
    if (!dns) {
        return XDP_PASS;
    }

    __u16 id = bpf_ntohs(dns->id);
    __u16 flags = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);
    __u8 is_response = (flags >> 15) & 0x1;

    // Only process DNS queries with exactly 1 question (ignore responses and multiple questions)
    if (qdcount != 1 || is_response == 1) {
        return XDP_PASS;
    }

    bpf_info("[XDP] DNS Query: ID=0x%04x Flags=0x%04x", id, flags);

    __u32 name_hash = 0;
    if (calculate_dns_name_hash(&cursor, data_end, &name_hash) < 0) {
        bpf_warn("[XDP] Hash failed: ID=0x%04x (truncated/invalid)", id);
        return XDP_PASS;
    }

    if (cursor + 4 > data_end) {
        return XDP_PASS;
    }
    __u16 qtype = read_u16_unaligned(cursor);
    __u16 qclass = read_u16_unaligned(cursor + 2);

    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    bpf_debug("[XDP] Key: Hash=0x%x Type=%d Class=%d", key.name_hash, key.qtype, key.qclass);

    // TODO: bpf_map_lookup_elem(&cache_map, &key);

    return XDP_PASS;
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

    __u64 dns_offset = (void*)(udp + 1) - data;
    if (dns_offset > skb->len) {
        return TC_ACT_OK;
    }

    __u32 dns_len = skb->len - dns_offset;
    if (dns_len > MAX_DNS_CAPTURE_LEN) {
        dns_len = MAX_DNS_CAPTURE_LEN;
    }

    struct dns_event* e = bpf_ringbuf_reserve(&rb_pkt, sizeof(*e) + MAX_DNS_CAPTURE_LEN, 0);
    if (unlikely(!e)) {
        bpf_warn("[TC] RingBuf full, dropped DNS Resp (len=%u)", skb->len);
        return TC_ACT_OK;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->len = dns_len;

    bpf_skb_load_bytes(skb, dns_offset, e->payload, dns_len);

    bpf_ringbuf_submit(e, 0);
    bpf_info("[TC] Captured DNS Resp: len=%u saved=%u", skb->len, dns_len);

    return TC_ACT_OK;
}
