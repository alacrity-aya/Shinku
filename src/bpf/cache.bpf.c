// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/cache_bpf_state.h"

char LICENSE[] SEC("license") = "GPL";

#include "bpf/cache_bpf_fingerprint.h"
#include "bpf/cache_bpf_parse.h"
#include "bpf/cache_bpf_pending.h"
#include "bpf/cache_bpf_snapshot.h"

SEC("xdp")
int xdp_rx(struct xdp_md* context) {
    void* data = (void*)(long)context->data;
    void* data_end = (void*)(long)context->data_end;
    struct packet_view query = {};
    if (!parse_envelope(data, data_end, true, &query))
        return XDP_PASS;

    const __u32 zero = 0;
    struct packet_scratch* scratch = bpf_map_lookup_elem(&packet_scratch_map, &zero);
    if (!scratch)
        return XDP_PASS;
    struct question_facts question = {};
    if (!parse_question(query.dns, data_end, query.dns_size, scratch, &question) || !eligible_query(&query, &question))
        return XDP_PASS;

    struct ebpf_cache_fingerprint fingerprint;
    if (!question_fingerprint(scratch, &question, &fingerprint))
        return XDP_PASS;
    const __be32 query_source_ipv4 = query.ip->saddr;
    const __be32 query_destination_ipv4 = query.ip->daddr;
    const __be16 query_source_port = query.udp->source;
    const __be16 query_destination_port = query.udp->dest;
    const __be16 query_transaction_id = query.dns->id;
    const struct ebpf_cache_physical_key cache_key = {
        .destination_ipv4 = query_destination_ipv4,
        .destination_port = query_destination_port,
        .reserved = 0,
        .fingerprint = fingerprint,
    };
    const struct ebpf_cache_publication* publication = bpf_map_lookup_elem(&cache_map, &cache_key);
    if (publication) {
        const int action = serve_hit(context, &query, &question, scratch, publication);
        if (action != XDP_PASS)
            return action; // return XDP_TX here
    }

    const __u64 now = bpf_ktime_get_boot_ns();
    const struct ebpf_pending_query_key pending_key = {
        .source_ipv4 = query_source_ipv4,
        .destination_ipv4 = query_destination_ipv4,
        .source_port = query_source_port,
        .destination_port = query_destination_port,
        .transaction_id = query_transaction_id,
        .reserved = 0,
    };
    remember_pending(&pending_key, &fingerprint, now);
    return XDP_PASS;
}

SEC("tc")
int tc_tx(struct __sk_buff* skb) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct packet_view response = {};
    if (!parse_envelope(data, data_end, false, &response))
        return SHINKU_TC_ACT_OK;
    __u32 response_size = response.dns_size;
    if (response_size > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES)
        return SHINKU_TC_ACT_OK;
    response_size &= 0x3ffU;
    barrier_var(response_size);
    if (response_size < SHINKU_DNS_HEADER_BYTES || response_size > SHINKU_EBPF_CACHE_MAX_RESPONSE_BYTES)
        return SHINKU_TC_ACT_OK;

    const __u32 zero = 0;
    struct packet_scratch* scratch = bpf_map_lookup_elem(&packet_scratch_map, &zero);
    if (!scratch)
        return SHINKU_TC_ACT_OK;
    struct question_facts question = {};
    if (!parse_question(response.dns, data_end, response.dns_size, scratch, &question)
        || !response_question(&response, &question))
        return SHINKU_TC_ACT_OK;

    const struct ebpf_pending_query_key pending_key = {
        .source_ipv4 = response.ip->daddr,
        .destination_ipv4 = response.ip->saddr,
        .source_port = response.udp->dest,
        .destination_port = response.udp->source,
        .transaction_id = response.dns->id,
        .reserved = 0,
    };
    struct ebpf_pending_query_value* pending = bpf_map_lookup_elem(&pending_queries, &pending_key);
    if (!pending)
        return SHINKU_TC_ACT_OK;
    struct ebpf_cache_fingerprint fingerprint;
    if (!question_fingerprint(scratch, &question, &fingerprint))
        return SHINKU_TC_ACT_OK;
    if (!same_fingerprint(&pending->fingerprint, &fingerprint))
        return SHINKU_TC_ACT_OK;

    __u64 state = READ_ONCE(pending->state_and_last_seen_ns);
    if ((state & SHINKU_EBPF_PENDING_CLAIMED) != 0)
        return SHINKU_TC_ACT_OK;
    const __u64 observed_at = bpf_ktime_get_boot_ns();
    const __u64 last_seen = state & SHINKU_EBPF_PENDING_TIME_MASK;
    if ((observed_at & SHINKU_EBPF_PENDING_CLAIMED) != 0 || observed_at < last_seen
        || observed_at - last_seen >= shinku_config.pending_timeout_ns)
        return SHINKU_TC_ACT_OK;

    struct ebpf_correlated_dns_event* event = bpf_ringbuf_reserve(&rb_pkt, sizeof(*event), 0);
    if (!event)
        return SHINKU_TC_ACT_OK;
    event->response_observed_at_ns = observed_at;
    event->destination_ipv4 = pending_key.destination_ipv4;
    event->destination_port = pending_key.destination_port;
    event->response_size = bpf_htons((__u16)response_size);
    const __u32 dns_offset = (__u32)((__u8*)response.dns - (__u8*)data);
    if (bpf_skb_load_bytes(skb, dns_offset, event->response, response_size) != 0) {
        bpf_ringbuf_discard(event, 0);
        return SHINKU_TC_ACT_OK;
    }

    bool claimed = false;
#pragma clang loop unroll(full)
    for (int attempt = 0; attempt < 2; ++attempt) {
        if ((state & SHINKU_EBPF_PENDING_CLAIMED) != 0)
            break;
        const __u64 claim = state | SHINKU_EBPF_PENDING_CLAIMED;
        const __u64 previous = __sync_val_compare_and_swap(&pending->state_and_last_seen_ns, state, claim);
        if (previous == state) {
            claimed = true;
            break;
        }
        state = previous;
        const __u64 refreshed_last_seen = state & SHINKU_EBPF_PENDING_TIME_MASK;
        if (observed_at < refreshed_last_seen || observed_at - refreshed_last_seen >= shinku_config.pending_timeout_ns)
            break;
    }
    if (!claimed) {
        bpf_ringbuf_discard(event, 0);
        return SHINKU_TC_ACT_OK;
    }

    bpf_ringbuf_submit(event, 0);
    return SHINKU_TC_ACT_OK;
}
