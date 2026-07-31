// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "ebpf_cache_abi.h"

#ifndef __always_inline
    #define __always_inline inline __attribute__((always_inline))
#endif

struct shinku_siphash128_state {
    __u64 v0;
    __u64 v1;
    __u64 v2;
    __u64 v3;
    __u64 tail;
    __u64 length;
    __u32 tail_size;
};

static __always_inline __u64 shinku_rotl64(__u64 value, __u32 shift) {
    return (value << shift) | (value >> (64U - shift));
}

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

static __always_inline void shinku_siphash128_compress(struct shinku_siphash128_state* state, __u64 word) {
    state->v3 ^= word;
    shinku_sipround(state);
    shinku_sipround(state);
    state->v0 ^= word;
}

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
