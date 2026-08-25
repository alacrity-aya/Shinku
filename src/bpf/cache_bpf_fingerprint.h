// SPDX-License-Identifier: GPL-2.0-only
/* Canonical-question fingerprinting (SipHash-128) for the cache BPF program. */
#pragma once

#include "bpf/cache_bpf_state.h"

/// Scratch state shared by the SipHash block-compression bpf_loop callback.
struct fingerprint_context {
    struct shinku_siphash128_state state; ///< Streaming SipHash state being fed 64-bit words.
    const __u8* canonical_question;       ///< Canonical question bytes to hash.
    __u32 full_block_count;               ///< Number of full 8-byte blocks in the input.
    __u32 invalid;                        ///< Set to 1 by the callback when a bounds check fails.
};

/**
 * @brief bpf_loop callback compressing one 8-byte block of the canonical question into the SipHash state.
 *
 * Loads the block little-endian and absorbs it via shinku_siphash128_compress;
 * marks the context invalid and aborts the loop if the index exceeds the block
 * count or the 32-block cap.
 */
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

/**
 * @brief Compute the SipHash-128 fingerprint of the canonical question.
 *
 * Appends the QTYPE and QCLASS in big-endian byte order to the canonical name,
 * hashes the full 8-byte blocks via bpf_loop, absorbs the tail bytes, and
 * finalizes the fingerprint. The host must derive the same value for identical
 * inputs.
 * @param scratch Scratch buffer holding the canonical question bytes.
 * @param question Parsed question facts (name size, type, class).
 * @param fingerprint Receives the 128-bit fingerprint on success.
 * @return True if the input was a valid size and the hash completed in bounds.
 */
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

/**
 * @brief Return true if two fingerprints are equal.
 * @param lhs First fingerprint.
 * @param rhs Second fingerprint.
 */
static __always_inline bool
same_fingerprint(const struct ebpf_cache_fingerprint* lhs, const struct ebpf_cache_fingerprint* rhs) {
    return lhs->first == rhs->first && lhs->second == rhs->second;
}
