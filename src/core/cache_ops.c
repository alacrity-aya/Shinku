// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_ops.h"

#include <bpf/bpf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static inline uint32_t ring_buffer_alloc_idx(atomic_uint* next_idx, uint32_t max_entries) {
    uint32_t idx = atomic_fetch_add_explicit(next_idx, 1, memory_order_relaxed);
    return idx % max_entries;
}

static inline void seqlock_write_begin(atomic_uint* seq) {
    atomic_fetch_add_explicit(seq, 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void seqlock_write_end(atomic_uint* seq) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_fetch_add_explicit(seq, 1, memory_order_release);
}

int dns_cache_store_response_with_flags(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope,
    uint8_t flags
) {
    if (!cache_ctx || !cache_ctx->entries || !cache_ctx->next_idx)
        return -1;

    if (flat_len > ARENA_ENTRY_SIZE || flat_len <= 0)
        return -1;

    if (!cache_ctx->slot_owners) {
        degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 0);
        obs_metrics_count_cache_insert(runtime && runtime->obs ? runtime->obs->metrics : NULL, 0);
        obs_metrics_mark_degraded(
            runtime && runtime->obs ? runtime->obs->metrics : NULL,
            OBS_DEGRADED_CACHE_MAP_UPDATE_FAIL
        );
        return -1;
    }

    uint32_t idx = ring_buffer_alloc_idx((atomic_uint*)cache_ctx->next_idx, cache_ctx->max_entries);

    if (cache_ctx->cache_map_fd < 0)
        return -1;

    uint32_t gen = ++cache_ctx->next_gen;

    seqlock_write_begin((atomic_uint*)&cache_ctx->entries[idx].seq);
    cache_ctx->entries[idx].gen = gen;
    memcpy(cache_ctx->entries[idx].pkt, flat_buf, flat_len);
    seqlock_write_end((atomic_uint*)&cache_ctx->entries[idx].seq);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;

    struct cache_value val = {
        .arena_idx = idx,
        .expire_ts = now_ns + ((uint64_t)min_ttl * 1000000000ULL),
        .pkt_len = (uint16_t)flat_len,
        .scope = ecs_scope,
        .flags = flags,
        .gen = gen,
    };

    if (cache_ctx->slot_owners_lock)
        pthread_mutex_lock(cache_ctx->slot_owners_lock);

    struct cache_key* old_key = &cache_ctx->slot_owners[idx];
    if (old_key->name_hash != 0 || old_key->qtype != 0) {
        struct cache_value old_val;
        int old_lookup_err = bpf_map_lookup_elem(cache_ctx->cache_map_fd, old_key, &old_val);
        if (old_lookup_err == 0 && old_val.arena_idx == idx)
            bpf_map_delete_elem(cache_ctx->cache_map_fd, old_key);
    }

    cache_ctx->slot_owners[idx] = *key;

    int err = bpf_map_update_elem(cache_ctx->cache_map_fd, key, &val, BPF_ANY);
    if (err) {
        if (cache_ctx->slot_owners_lock)
            pthread_mutex_unlock(cache_ctx->slot_owners_lock);
        fprintf(stderr, "[Cache] bpf_map_update_elem failed: %d\n", err);
        degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 0);
        obs_metrics_count_cache_insert(runtime && runtime->obs ? runtime->obs->metrics : NULL, 0);
        return -1;
    }

    if (cache_ctx->slot_owners_lock)
        pthread_mutex_unlock(cache_ctx->slot_owners_lock);

    degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 1);

    printf(
        "[Cache] Stored: Hash=0x%x Idx=%u Size=%d TTL=%us Gen=%u\n",
        key->name_hash,
        idx,
        flat_len,
        min_ttl,
        gen
    );
    obs_metrics_count_cache_insert(runtime && runtime->obs ? runtime->obs->metrics : NULL, 1);
    return 0;
}

int dns_cache_store_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* flat_buf,
    int flat_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
) {
    return dns_cache_store_response_with_flags(
        cache_ctx,
        runtime,
        key,
        flat_buf,
        flat_len,
        min_ttl,
        ecs_scope,
        0
    );
}

int dns_cache_store_raw_response(
    struct cache_context* cache_ctx,
    struct dns_parser_runtime* runtime,
    struct cache_key* key,
    uint8_t* pkt_buf,
    int pkt_len,
    uint32_t min_ttl,
    uint8_t ecs_scope
) {
    return dns_cache_store_response_with_flags(
        cache_ctx,
        runtime,
        key,
        pkt_buf,
        pkt_len,
        min_ttl,
        ecs_scope,
        0
    );
}

int dns_cache_cleanup_expired_entries(struct cache_context* cache_ctx) {
    if (!cache_ctx || cache_ctx->cache_map_fd < 0)
        return -1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;

    struct cache_key key = { 0 };
    struct cache_key next_key = { 0 };
    struct cache_key expired_keys[256];
    int expired_count = 0;

    int err = bpf_map_get_next_key(cache_ctx->cache_map_fd, NULL, &next_key);
    while (err == 0 && expired_count < 256) {
        key = next_key;
        err = bpf_map_get_next_key(cache_ctx->cache_map_fd, &key, &next_key);

        struct cache_value val;
        if (bpf_map_lookup_elem(cache_ctx->cache_map_fd, &key, &val) == 0) {
            if (now_ns >= val.expire_ts)
                expired_keys[expired_count++] = key;
        }
    }

    for (int i = 0; i < expired_count; i++) {
        struct cache_value cur_val;
        if (bpf_map_lookup_elem(cache_ctx->cache_map_fd, &expired_keys[i], &cur_val) == 0
            && now_ns >= cur_val.expire_ts)
        {
            int del_err = bpf_map_delete_elem(cache_ctx->cache_map_fd, &expired_keys[i]);
            if (del_err == 0) {
                uint32_t idx = cur_val.arena_idx;
                if (cache_ctx->slot_owners && idx < cache_ctx->max_entries) {
                    if (cache_ctx->slot_owners_lock)
                        pthread_mutex_lock(cache_ctx->slot_owners_lock);

                    if (memcmp(
                            &cache_ctx->slot_owners[idx],
                            &expired_keys[i],
                            sizeof(struct cache_key)
                        )
                        == 0)
                    {
                        memset(&cache_ctx->slot_owners[idx], 0, sizeof(struct cache_key));
                    }

                    if (cache_ctx->slot_owners_lock)
                        pthread_mutex_unlock(cache_ctx->slot_owners_lock);
                }
            }
        }
    }

    if (expired_count > 0)
        printf("[Cache] Cleanup: removed %d expired entries\n", expired_count);

    return expired_count;
}
