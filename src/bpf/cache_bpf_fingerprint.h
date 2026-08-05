// SPDX-License-Identifier: GPL-2.0-only
/* Canonical-question fingerprinting (SipHash-128) for the cache BPF program. */
#pragma once

#include "bpf/cache_bpf_state.h"

struct fingerprint_context {
    struct shinku_siphash128_state state;
    const __u8* canonical_question;
    __u32 full_block_count;
    __u32 invalid;
};

static long fingerprint_block_callback(__u32 index, void* opaque) {
    struct fingerprint_context* context = opaque;
    if (index >= context->full_block_count || index >= 32U) {
        context->invalid = 1;
        return 1;
    }
    const __u32 offset = index * 8U;
    const __u8* block = context->canonical_question + offset;
    const __u64 word = (__u64)block[0] | ((__u64)block[1] << 8U) | ((__u64)block[2] << 16U) | ((__u64)block[3] << 24U)
        | ((__u64)block[4] << 32U) | ((__u64)block[5] << 40U) | ((__u64)block[6] << 48U) | ((__u64)block[7] << 56U);
    shinku_siphash128_compress(&context->state, word);
    return 0;
}

static __always_inline bool question_fingerprint(
    struct packet_scratch* scratch,
    const struct question_facts* question,
    struct ebpf_cache_fingerprint* fingerprint
) {
    if (question->qname_size == 0 || question->qname_size > 255U)
        return false;
    const __u32 input_size = (__u32)question->qname_size + 4U;
    if (input_size > 259U)
        return false;

    const __u16 question_type = bpf_ntohs(question->question_type);
    const __u16 question_class = bpf_ntohs(question->question_class);
    scratch->canonical_question[question->qname_size] = (__u8)(question_type >> 8U);
    scratch->canonical_question[question->qname_size + 1U] = (__u8)question_type;
    scratch->canonical_question[question->qname_size + 2U] = (__u8)(question_class >> 8U);
    scratch->canonical_question[question->qname_size + 3U] = (__u8)question_class;

    const __u32 full_block_count = input_size / 8U;
    const struct ebpf_cache_secret secret = {
        .first = shinku_config.secret.first,
        .second = shinku_config.secret.second,
    };
    struct fingerprint_context context = {
        .canonical_question = scratch->canonical_question,
        .full_block_count = full_block_count,
        .invalid = 0,
    };
    shinku_siphash128_init(&context.state, &secret);
    if (bpf_loop(full_block_count, fingerprint_block_callback, &context, 0) < 0 || context.invalid != 0)
        return false;

    const __u32 tail_offset = full_block_count * 8U;
    const __u32 tail_size = input_size - tail_offset;
    if (tail_offset > 256U || tail_size > 7U)
        return false;
    __u64 tail = 0;
#pragma clang loop unroll(full)
    for (__u32 index = 0; index < 7U; ++index) {
        if (index >= tail_size)
            break;
        tail |= (__u64)scratch->canonical_question[tail_offset + index] << (index * 8U);
    }
    context.state.tail = tail;
    context.state.tail_size = tail_size;
    context.state.length = input_size;
    *fingerprint = shinku_siphash128_finish(&context.state);
    return true;
}

static __always_inline bool
same_fingerprint(const struct ebpf_cache_fingerprint* lhs, const struct ebpf_cache_fingerprint* rhs) {
    return lhs->first == rhs->first && lhs->second == rhs->second;
}
