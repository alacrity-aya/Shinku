// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#ifndef __always_inline
    #define __always_inline inline __attribute__((always_inline))
#endif

/**
 * @file ebpf_cache_fingerprint.h
 * @brief SipHash-2-4 (128-bit) fingerprint shared by the host and BPF programs.
 *
 * Both the host store and the BPF hit path use the same keyed SipHash to map
 * a (canonical name, QTYPE, QCLASS) triple to a 128-bit fingerprint, so that
 * keys collide only by cryptographic coincidence rather than by raw identity.
 * The host and BPF sides must produce byte-identical output for the same
 * input and secret; the implementation here is the shared reference.
 */

/// State for the streaming SipHash-2-4 (128-bit) computation.
struct shinku_siphash128_state {
    __u64 v0; ///< Internal SipHash state word 0.
    __u64 v1; ///< Internal SipHash state word 1.
    __u64 v2; ///< Internal SipHash state word 2.
    __u64 v3; ///< Internal SipHash state word 3.
    __u64 tail; ///< Accumulated partial-word bytes not yet compressed.
    __u64 length; ///< Total input length processed so far.
    __u32 tail_size; ///< Number of bytes currently held in @ref tail.
};

/// @brief Rotate a 64-bit @p value left by @p shift bits.
static __always_inline __u64 shinku_rotl64(__u64 value, __u32 shift) {
    return (value << shift) | (value >> (64U - shift));
}

/// @brief Perform one SipHash round on @p state.
static __always_inline void shinku_sipround(struct shinku_siphash128_state* state) {
    state->v0 += state->v1;
    state->v1 = shinku_rotl64(state->v1, 13);
    state->v1 ^= state->v0;
    state->v0 = shinku_rotl64(state->v0, 32);
    state->v2 += state->v3;
    state->v3 = shinku_rotl64(state->v3, 16);
    state->v3 ^= state->v2;
    state->v0 += state->v3;
    state->v3 = shinku_rotl64(state->v3, 21);
    state->v3 ^= state->v0;
    state->v2 += state->v1;
    state->v1 = shinku_rotl64(state->v1, 17);
    state->v1 ^= state->v2;
    state->v2 = shinku_rotl64(state->v2, 32);
}

/**
 * @brief Initialize the SipHash state keyed with @p secret.
 * @param state The state to initialize.
 * @param secret The 128-bit secret keying the hash.
 */
static __always_inline void
shinku_siphash128_init(struct shinku_siphash128_state* state, const struct ebpf_cache_secret* secret) {
    state->v0 = 0x736f6d6570736575ULL ^ secret->first;
    state->v1 = 0x646f72616e646f6dULL ^ secret->second;
    state->v2 = 0x6c7967656e657261ULL ^ secret->first;
    state->v3 = 0x7465646279746573ULL ^ secret->second;
    state->v1 ^= 0xeeULL;
    state->tail = 0;
    state->length = 0;
    state->tail_size = 0;
}

/**
 * @brief Compress one 64-bit @p word into @p state (two SipHash rounds).
 * @param state The hash state.
 * @param word The 64-bit word to absorb.
 */
static __always_inline void shinku_siphash128_compress(struct shinku_siphash128_state* state, __u64 word) {
    state->v3 ^= word;
    shinku_sipround(state);
    shinku_sipround(state);
    state->v0 ^= word;
}

/**
 * @brief Feed a single @p byte into @p state, flushing a word when one is full.
 * @param state The hash state.
 * @param byte The byte to absorb.
 */
static __always_inline void shinku_siphash128_update_byte(struct shinku_siphash128_state* state, __u8 byte) {
    state->tail |= ((__u64)byte) << (state->tail_size * 8U);
    ++state->tail_size;
    ++state->length;
    if (state->tail_size == 8U) {
        shinku_siphash128_compress(state, state->tail);
        state->tail = 0;
        state->tail_size = 0;
    }
}

/**
 * @brief Finalize the hash and produce the 128-bit fingerprint.
 * @param state The hash state (consumed).
 * @return The 128-bit @ref ebpf_cache_fingerprint.
 */
static __always_inline struct ebpf_cache_fingerprint shinku_siphash128_finish(struct shinku_siphash128_state* state) {
    const __u64 final_word = state->tail | ((state->length & 0xffULL) << 56U);
    shinku_siphash128_compress(state, final_word);
    state->v2 ^= 0xeeULL;
    shinku_sipround(state);
    shinku_sipround(state);
    shinku_sipround(state);
    shinku_sipround(state);

    struct ebpf_cache_fingerprint result = {
        .first = state->v0 ^ state->v1 ^ state->v2 ^ state->v3,
        .second = 0,
    };

    state->v1 ^= 0xddULL;
    shinku_sipround(state);
    shinku_sipround(state);
    shinku_sipround(state);
    shinku_sipround(state);
    result.second = state->v0 ^ state->v1 ^ state->v2 ^ state->v3;
    return result;
}

/**
 * @brief Compute the 128-bit fingerprint of a DNS question triple.
 *
 * Hashes the canonical name (up to 255 bytes), then the QTYPE and QCLASS in
 * big-endian byte order, using @p secret as the key. The host and BPF sides
 * must call this with identical inputs to obtain matching fingerprints.
 *
 * @param canonical_name Canonical wire-format name bytes.
 * @param canonical_name_size Number of valid bytes in @p canonical_name.
 * @param question_type The DNS QTYPE.
 * @param question_class The DNS QCLASS.
 * @param secret The 128-bit secret keying the hash.
 * @return The 128-bit @ref ebpf_cache_fingerprint.
 */
static __always_inline struct ebpf_cache_fingerprint shinku_ebpf_cache_fingerprint(
    const __u8* canonical_name,
    __u32 canonical_name_size,
    __u16 question_type,
    __u16 question_class,
    const struct ebpf_cache_secret* secret
) {
    struct shinku_siphash128_state state;
    shinku_siphash128_init(&state, secret);

    for (__u32 index = 0; index < 255U; ++index) {
        if (index >= canonical_name_size)
            break;
        shinku_siphash128_update_byte(&state, canonical_name[index]);
    }

    shinku_siphash128_update_byte(&state, (__u8)(question_type >> 8U));
    shinku_siphash128_update_byte(&state, (__u8)question_type);
    shinku_siphash128_update_byte(&state, (__u8)(question_class >> 8U));
    shinku_siphash128_update_byte(&state, (__u8)question_class);
    return shinku_siphash128_finish(&state);
}
