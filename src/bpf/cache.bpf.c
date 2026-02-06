#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <common/bpf_log.h>
#include <common/types.h>
#include <utils/hash.h>
#include <utils/parser.h>

char LICENSE[] SEC("license") = "GPL";

static __always_inline __u16 read_u16_unaligned(void* ptr) {
    __u8* b = (__u8*)ptr;
    return (b[0] << 8) | b[1];
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB
} rb_pkt SEC(".maps");

SEC("xdp")
int xdp_rx(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    void* cursor = NULL;

    bpf_debug("[XDP] RX pkt len=%lu", (__u32)(data_end - data));

    struct dns_hdr* dns = parse_dns_header(ctx, &cursor, data_end);
    if (!dns) {
        return XDP_PASS;
    }

    __u16 id = bpf_ntohs(dns->id);
    __u16 flags = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);
    __u8 is_response = (flags >> 15) & 0x1;

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

SEC("tc")
int tc_tx(struct __sk_buff* skb) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = eth->h_proto;
    void* next_hdr = (void*)(eth + 1);

    // skip vlan
#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr* vlan = next_hdr;
            if ((void*)(vlan + 1) > data_end)
                return TC_ACT_OK;

            proto = vlan->h_vlan_encapsulated_proto;
            next_hdr = (void*)(vlan + 1);
        } else {
            break;
        }
    }

    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr* ip = (void*)(eth + 1);
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

    __u32 pkt_len = skb->len;
    if (unlikely(pkt_len == 0)) {
        return TC_ACT_OK;
    }

    if (pkt_len > MAX_DNS_CAPTURE_LEN)
        pkt_len = MAX_DNS_CAPTURE_LEN;

    struct dns_event* e = bpf_ringbuf_reserve(&rb_pkt, sizeof(*e) + MAX_DNS_CAPTURE_LEN, 0);
    if (!e) {
        bpf_warn("[TC] RingBuf full, dropped DNS Resp (len=%u)", skb->len);
        return TC_ACT_OK;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->len = pkt_len;
    bpf_skb_load_bytes(skb, 0, e->payload, e->len);

    bpf_ringbuf_submit(e, 0);

    bpf_info("[TC] Captured DNS Resp: len=%u saved=%u", skb->len, pkt_len);

    return TC_ACT_OK;
}
