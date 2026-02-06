#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <common/bpf_log.h>
#include <common/types.h>
#include <utils/hash.h>
#include <utils/parser.h>

static __always_inline __u16 read_u16_unaligned(void* ptr) {
    __u8* b = (__u8*)ptr;
    return (b[0] << 8) | b[1];
}

SEC("xdp")
int xdp_rx(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = NULL;

    bpf_debug("xdp is called\n");

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

    bpf_info(
        "Query: ID=0x%x Flag=0x%x QDCOUNT=%d, IS_RESPONSE=%d",
        id,
        flags,
        qdcount,
        is_response,
    );

    __u32 name_hash = 0;
    if (calculate_dns_name_hash(&cursor, data_end, &name_hash) < 0) {
        bpf_warn("Failed to calculate hash (truncated or too long)");
        return XDP_PASS;
    }

    if (cursor + 4 > data_end) {
        return XDP_PASS;
    }
    __u16 qtype = read_u16_unaligned(cursor);
    __u16 qclass = read_u16_unaligned(cursor + 2);

    struct cache_key key = { .name_hash = name_hash, .qtype = qtype, .qclass = qclass, ._pad = 0 };

    bpf_info("Query: ID=0x%x Hash=0x%x Type=%d", id, key.name_hash, key.qtype);

    // TODO: bpf_map_lookup_elem(&cache_map, &key);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
