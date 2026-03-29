// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_ops.h"

#include <bpf/bpf.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CACHE_SEQLOCK_STEP 1U
#define CACHE_KEY_EMPTY_HASH 0U
#define CACHE_KEY_EMPTY_QTYPE 0U
#define CACHE_ADMISSION_DEFAULT_FLAGS 0U
#define CACHE_NSEC_PER_SEC 1000000000ULL
#define CACHE_FREQ_ROWS 4U
#define CACHE_FREQ_ROW_SALT 0x9e3779b97f4a7c15ULL
#define CACHE_HASH_FNV_OFFSET_BASIS 1469598103934665603ULL
#define CACHE_HASH_FNV_PRIME 1099511628211ULL
#define CACHE_CLEANUP_BATCH_SIZE 256

static inline uint32_t ring_buffer_alloc_idx(atomic_uint* next_idx, uint32_t max_entries) {
    uint32_t idx = atomic_fetch_add_explicit(next_idx, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    return idx % max_entries;
}

static inline void seqlock_write_begin(atomic_uint* seq) {
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
}

static inline void seqlock_write_end(atomic_uint* seq) {
    atomic_thread_fence(memory_order_seq_cst);
    atomic_fetch_add_explicit(seq, CACHE_SEQLOCK_STEP, memory_order_release);
}

static inline uint64_t key_fingerprint(const struct cache_key* key) {
    uint64_t h = CACHE_HASH_FNV_OFFSET_BASIS;
#define MIX_BYTE(v) \
    do { \
        h ^= (uint64_t)(v); \
        h *= CACHE_HASH_FNV_PRIME; \
    } while (0)
    const uint8_t* p = (const uint8_t*)key;
    for (size_t i = 0; i < sizeof(*key); i++)
        MIX_BYTE(p[i]);
#undef MIX_BYTE
    return h;
}

static inline int keys_equal(const struct cache_key* a, const struct cache_key* b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

static inline uint32_t cm_index(uint64_t fp, uint32_t row, uint32_t width) {
    uint64_t mixed = fp ^ (CACHE_FREQ_ROW_SALT * (uint64_t)(row + 1U));
    return (uint32_t)(mixed % width);
}

static uint16_t cm_estimate(struct cache_context* cache_ctx, uint64_t fp) {
    if (!cache_ctx->freq_width || !cache_ctx->freq_rows[0])
        return 0;

    uint16_t est = UINT16_MAX;
    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = cache_ctx->freq_rows[r];
        if (!row)
            return 0;
        uint32_t idx = cm_index(fp, r, cache_ctx->freq_width);
        if (row[idx] < est)
            est = row[idx];
    }
    return est == UINT16_MAX ? 0 : est;
}

static void cm_decay(struct cache_context* cache_ctx) {
    if (!cache_ctx->freq_width)
        return;
    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = cache_ctx->freq_rows[r];
        if (!row)
            continue;
        for (uint32_t i = 0; i < cache_ctx->freq_width; i++)
            row[i] >>= 1;
    }
}

static void cm_increment(struct cache_context* cache_ctx, uint64_t fp) {
    if (!cache_ctx->freq_width || !cache_ctx->freq_rows[0])
        return;

    for (uint32_t r = 0; r < CACHE_FREQ_ROWS; r++) {
        uint16_t* row = cache_ctx->freq_rows[r];
        if (!row)
            continue;
        uint32_t idx = cm_index(fp, r, cache_ctx->freq_width);
        if (row[idx] < UINT16_MAX)
            row[idx]++;
    }

    cache_ctx->freq_ops++;
    if (cache_ctx->freq_epoch_ops > 0 && cache_ctx->freq_ops >= cache_ctx->freq_epoch_ops) {
        cm_decay(cache_ctx);
        cache_ctx->freq_ops = 0;
    }
}

static int was_inserted_recently(
    struct cache_context* cache_ctx,
    const struct cache_key* key,
    uint64_t now_ns
) {
    if (!cache_ctx->recent_insert_keys || !cache_ctx->recent_insert_ns
        || !cache_ctx->recent_insert_cap)
        return 0;
    if (!cache_ctx->admission_dampen_window_ns)
        return 0;

    for (uint32_t i = 0; i < cache_ctx->recent_insert_cap; i++) {
        if (cache_ctx->recent_insert_ns[i] == 0)
            continue;
        if (!keys_equal(&cache_ctx->recent_insert_keys[i], key))
            continue;
        if (now_ns - cache_ctx->recent_insert_ns[i] <= cache_ctx->admission_dampen_window_ns)
            return 1;
    }
    return 0;
}

static void
track_recent_insert(struct cache_context* cache_ctx, const struct cache_key* key, uint64_t now_ns) {
    if (!cache_ctx->recent_insert_keys || !cache_ctx->recent_insert_ns
        || !cache_ctx->recent_insert_cap)
        return;

    uint32_t pos = cache_ctx->recent_insert_next % cache_ctx->recent_insert_cap;
    cache_ctx->recent_insert_keys[pos] = *key;
    cache_ctx->recent_insert_ns[pos] = now_ns;
    cache_ctx->recent_insert_next = pos + 1;
}

static void
update_segment_metrics(struct dns_parser_runtime* runtime, struct cache_context* cache_ctx) {
    struct obs_metrics* metrics =
        runtime && runtime->obs ? runtime->obs->metrics : cache_ctx->metrics;

    if (!metrics || !metrics->cfg.enabled || !cache_ctx->slot_owners)
        return;

    uint32_t hot = 0;
    uint32_t cold = 0;
    for (uint32_t i = 0; i < cache_ctx->max_entries; i++) {
        const struct cache_key* owner = &cache_ctx->slot_owners[i];
        if (owner->name_hash == CACHE_KEY_EMPTY_HASH && owner->qtype == CACHE_KEY_EMPTY_QTYPE)
            continue;

        uint8_t is_hot = cache_ctx->slot_hot ? cache_ctx->slot_hot[i] : 0;
        if (is_hot)
            hot++;
        else
            cold++;
    }

    obs_metrics_set_cache_segment_sizes(metrics, hot, cold);
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

    if (cache_ctx->cache_map_fd < 0)
        return -1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = ((uint64_t)ts.tv_sec * CACHE_NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;

    obs_metrics_count_cache_admission_attempt(
        runtime && runtime->obs ? runtime->obs->metrics : NULL
    );

    if (cache_ctx->admission_enabled && flags == CACHE_ADMISSION_DEFAULT_FLAGS
        && cache_ctx->admission_min_ttl > 0 && min_ttl < cache_ctx->admission_min_ttl)
    {
        obs_metrics_count_cache_admission_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL
        );
        obs_metrics_count_cache_admission_reject_ttl(
            runtime && runtime->obs ? runtime->obs->metrics : NULL
        );
        return -1;
    }

    if (cache_ctx->admission_enabled && flags == CACHE_ADMISSION_DEFAULT_FLAGS
        && was_inserted_recently(cache_ctx, key, now_ns))
    {
        obs_metrics_count_cache_admission_reject(
            runtime && runtime->obs ? runtime->obs->metrics : NULL
        );
        obs_metrics_count_cache_admission_reject_recent(
            runtime && runtime->obs ? runtime->obs->metrics : NULL
        );
        return -1;
    }

    uint32_t idx = ring_buffer_alloc_idx((atomic_uint*)cache_ctx->next_idx, cache_ctx->max_entries);

    if (cache_ctx->admission_enabled && cache_ctx->pressure_mode && cache_ctx->slot_owners
        && cache_ctx->freq_width > 0)
    {
        struct cache_key* victim_key = &cache_ctx->slot_owners[idx];
        if ((victim_key->name_hash != CACHE_KEY_EMPTY_HASH
             || victim_key->qtype != CACHE_KEY_EMPTY_QTYPE)
            && !keys_equal(victim_key, key))
        {
            uint64_t cand_fp = key_fingerprint(key);
            uint64_t vict_fp = key_fingerprint(victim_key);
            uint16_t cand_f = cm_estimate(cache_ctx, cand_fp);
            uint16_t vict_f = cm_estimate(cache_ctx, vict_fp);
            int victim_hot = 0;
            if (cache_ctx->slot_hot)
                victim_hot = cache_ctx->slot_hot[idx] ? 1 : 0;
            if (!victim_hot && cache_ctx->hot_threshold > 0)
                victim_hot = vict_f >= cache_ctx->hot_threshold;

            if (cand_f <= vict_f && victim_hot) {
                obs_metrics_count_cache_admission_reject(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL
                );
                obs_metrics_count_cache_admission_reject_freq(
                    runtime && runtime->obs ? runtime->obs->metrics : NULL
                );
                return -1;
            }
        }
    }

    uint32_t gen = ++cache_ctx->next_gen;

    seqlock_write_begin((atomic_uint*)&cache_ctx->entries[idx].seq);
    cache_ctx->entries[idx].gen = gen;
    memcpy(cache_ctx->entries[idx].pkt, flat_buf, flat_len);
    seqlock_write_end((atomic_uint*)&cache_ctx->entries[idx].seq);

    struct cache_value val = {
        .arena_idx = idx,
        .expire_ts = now_ns + ((uint64_t)min_ttl * CACHE_NSEC_PER_SEC),
        .pkt_len = (uint16_t)flat_len,
        .scope = ecs_scope,
        .flags = flags,
        .gen = gen,
    };

    if (cache_ctx->slot_owners_lock)
        pthread_mutex_lock(cache_ctx->slot_owners_lock);

    struct cache_key* old_key = &cache_ctx->slot_owners[idx];
    struct cache_key old_key_copy = *old_key;
    int had_old =
        (old_key->name_hash != CACHE_KEY_EMPTY_HASH || old_key->qtype != CACHE_KEY_EMPTY_QTYPE);
    uint8_t old_hot = cache_ctx->slot_hot ? cache_ctx->slot_hot[idx] : 0;
    int rehit = had_old && keys_equal(&old_key_copy, key);
    int replacing_distinct = had_old && !rehit;

    cache_ctx->slot_owners[idx] = *key;

    uint64_t fp = key_fingerprint(key);
    uint32_t old_slot_hits = cache_ctx->slot_hit_count ? cache_ctx->slot_hit_count[idx] : 0;

    int err = bpf_map_update_elem(cache_ctx->cache_map_fd, key, &val, BPF_ANY);
    if (err) {
        cache_ctx->slot_owners[idx] = old_key_copy;
        if (cache_ctx->slot_hot)
            cache_ctx->slot_hot[idx] = old_hot;
        if (cache_ctx->slot_hit_count)
            cache_ctx->slot_hit_count[idx] = old_slot_hits;
        if (cache_ctx->slot_owners_lock)
            pthread_mutex_unlock(cache_ctx->slot_owners_lock);
        fprintf(stderr, "[Cache] bpf_map_update_elem failed: %d\n", err);
        degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 0);
        obs_metrics_count_cache_insert(runtime && runtime->obs ? runtime->obs->metrics : NULL, 0);
        return -1;
    }

    cm_increment(cache_ctx, fp);
    uint32_t cur_freq = cm_estimate(cache_ctx, fp);
    if (cache_ctx->slot_hit_count)
        cache_ctx->slot_hit_count[idx] = cur_freq;
    if (cache_ctx->slot_hot) {
        uint8_t promote = rehit ? 1 : 0;
        if (!promote && cache_ctx->hot_threshold > 0)
            promote = cur_freq >= cache_ctx->hot_threshold ? 1 : 0;
        cache_ctx->slot_hot[idx] = promote;
    }

    track_recent_insert(cache_ctx, key, now_ns);

    if (replacing_distinct) {
        obs_metrics_count_cache_eviction(
            runtime && runtime->obs ? runtime->obs->metrics : cache_ctx->metrics,
            old_hot ? 1 : 0
        );
        struct cache_value old_val;
        int old_lookup_err = bpf_map_lookup_elem(cache_ctx->cache_map_fd, &old_key_copy, &old_val);
        if (old_lookup_err == 0 && old_val.arena_idx == idx)
            bpf_map_delete_elem(cache_ctx->cache_map_fd, &old_key_copy);
    }

    update_segment_metrics(runtime, cache_ctx);

    if (cache_ctx->slot_owners_lock)
        pthread_mutex_unlock(cache_ctx->slot_owners_lock);

    obs_metrics_count_cache_admission_accept(
        runtime && runtime->obs ? runtime->obs->metrics : NULL
    );

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
        CACHE_ADMISSION_DEFAULT_FLAGS
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
        CACHE_ADMISSION_DEFAULT_FLAGS
    );
}

int dns_cache_cleanup_expired_entries(struct cache_context* cache_ctx) {
    if (!cache_ctx || cache_ctx->cache_map_fd < 0)
        return -1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = ((uint64_t)ts.tv_sec * CACHE_NSEC_PER_SEC) + (uint64_t)ts.tv_nsec;

    struct cache_key key = { 0 };
    struct cache_key next_key = { 0 };
    struct cache_key expired_keys[CACHE_CLEANUP_BATCH_SIZE];
    int expired_count = 0;

    int err = bpf_map_get_next_key(cache_ctx->cache_map_fd, NULL, &next_key);
    while (err == 0 && expired_count < CACHE_CLEANUP_BATCH_SIZE) {
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
                        if (cache_ctx->slot_hot)
                            cache_ctx->slot_hot[idx] = 0;
                    }

                    update_segment_metrics(NULL, cache_ctx);

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
