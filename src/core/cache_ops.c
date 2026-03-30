// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "cache_ops.h"
#include "cache_ops_internal.h"

#include <bpf/bpf.h>
#include <degraded_mode.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

    obs_metrics_count_cache_admission_attempt(runtime && runtime->obs ? runtime->obs->metrics : NULL);

    if (cache_ctx->admission.enabled && flags == CACHE_ADMISSION_DEFAULT_FLAGS && cache_ctx->admission.min_ttl > 0
        && min_ttl < cache_ctx->admission.min_ttl)
    {
        obs_metrics_count_cache_admission_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL);
        obs_metrics_count_cache_admission_reject_ttl(runtime && runtime->obs ? runtime->obs->metrics : NULL);
        return -1;
    }

    if (cache_ctx->admission.enabled && flags == CACHE_ADMISSION_DEFAULT_FLAGS
        && cache_recent_was_inserted(&cache_ctx->recent, cache_ctx->admission.dampen_window_ns, key, now_ns))
    {
        obs_metrics_count_cache_admission_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL);
        obs_metrics_count_cache_admission_reject_recent(runtime && runtime->obs ? runtime->obs->metrics : NULL);
        return -1;
    }

    uint32_t idx = ring_buffer_alloc_idx((atomic_uint*)cache_ctx->next_idx, cache_ctx->max_entries);

    if (cache_ctx->admission.enabled && cache_ctx->admission.pressure_mode && cache_ctx->slot_owners
        && cache_ctx->sketch.width > 0)
    {
        struct cache_key* victim_key = &cache_ctx->slot_owners[idx];
        if ((victim_key->name_hash != CACHE_KEY_EMPTY_HASH || victim_key->qtype != CACHE_KEY_EMPTY_QTYPE)
            && !keys_equal(victim_key, key))
        {
            uint64_t cand_fp = key_fingerprint(key);
            uint64_t vict_fp = key_fingerprint(victim_key);
            uint16_t cand_f = cache_cm_estimate(&cache_ctx->sketch, cand_fp);
            uint16_t vict_f = cache_cm_estimate(&cache_ctx->sketch, vict_fp);
            int victim_hot = 0;
            if (cache_ctx->segments.slot_hot)
                victim_hot = cache_ctx->segments.slot_hot[idx] ? 1 : 0;
            if (!victim_hot && cache_ctx->segments.hot_threshold > 0)
                victim_hot = vict_f >= cache_ctx->segments.hot_threshold;

            if (cand_f <= vict_f && victim_hot) {
                obs_metrics_count_cache_admission_reject(runtime && runtime->obs ? runtime->obs->metrics : NULL);
                obs_metrics_count_cache_admission_reject_freq(runtime && runtime->obs ? runtime->obs->metrics : NULL);
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
    int had_old = (old_key->name_hash != CACHE_KEY_EMPTY_HASH || old_key->qtype != CACHE_KEY_EMPTY_QTYPE);
    uint8_t old_hot = cache_ctx->segments.slot_hot ? cache_ctx->segments.slot_hot[idx] : 0;
    int rehit = had_old && keys_equal(&old_key_copy, key);
    int replacing_distinct = had_old && !rehit;

    cache_ctx->slot_owners[idx] = *key;

    uint64_t fp = key_fingerprint(key);
    uint32_t old_slot_hits = cache_ctx->segments.slot_hit_count ? cache_ctx->segments.slot_hit_count[idx] : 0;

    int err = bpf_map_update_elem(cache_ctx->cache_map_fd, key, &val, BPF_ANY);
    if (err) {
        cache_ctx->slot_owners[idx] = old_key_copy;
        if (cache_ctx->segments.slot_hot)
            cache_ctx->segments.slot_hot[idx] = old_hot;
        if (cache_ctx->segments.slot_hit_count)
            cache_ctx->segments.slot_hit_count[idx] = old_slot_hits;
        if (cache_ctx->slot_owners_lock)
            pthread_mutex_unlock(cache_ctx->slot_owners_lock);
        fprintf(stderr, "[Cache] bpf_map_update_elem failed: %d\n", err);
        degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 0);
        obs_metrics_count_cache_insert(runtime && runtime->obs ? runtime->obs->metrics : NULL, 0);
        return -1;
    }

    cache_cm_increment(&cache_ctx->sketch, fp);
    uint32_t cur_freq = cache_cm_estimate(&cache_ctx->sketch, fp);
    if (cache_ctx->segments.slot_hit_count)
        cache_ctx->segments.slot_hit_count[idx] = cur_freq;
    if (cache_ctx->segments.slot_hot) {
        uint8_t promote = cache_segments_calc_slot_hot(&cache_ctx->segments, rehit, cur_freq);
        cache_ctx->segments.slot_hot[idx] = promote;
        cache_segments_adjust_counts(&cache_ctx->segments, had_old, old_hot, promote, replacing_distinct);
    }

    cache_recent_track_insert(&cache_ctx->recent, key, now_ns);

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

    cache_segments_update_metrics(runtime, cache_ctx->metrics, &cache_ctx->segments);

    if (cache_ctx->slot_owners_lock)
        pthread_mutex_unlock(cache_ctx->slot_owners_lock);

    obs_metrics_count_cache_admission_accept(runtime && runtime->obs ? runtime->obs->metrics : NULL);

    degraded_note_cache_map_update(runtime ? runtime->degraded : NULL, 1);

    printf("[Cache] Stored: Hash=0x%x Idx=%u Size=%d TTL=%us Gen=%u\n", key->name_hash, idx, flat_len, min_ttl, gen);
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
    struct cache_value expired_vals[CACHE_CLEANUP_BATCH_SIZE];
    int expired_count = 0;

    int err = bpf_map_get_next_key(cache_ctx->cache_map_fd, NULL, &next_key);
    while (err == 0 && expired_count < CACHE_CLEANUP_BATCH_SIZE) {
        key = next_key;
        err = bpf_map_get_next_key(cache_ctx->cache_map_fd, &key, &next_key);

        struct cache_value val;
        if (bpf_map_lookup_elem(cache_ctx->cache_map_fd, &key, &val) == 0) {
            if (now_ns >= val.expire_ts) {
                expired_keys[expired_count++] = key;
                expired_vals[expired_count - 1] = val;
            }
        }
    }

    for (int i = 0; i < expired_count; i++) {
        int del_err = bpf_map_delete_elem(cache_ctx->cache_map_fd, &expired_keys[i]);
        if (del_err == 0) {
            uint32_t idx = expired_vals[i].arena_idx;
            if (cache_ctx->slot_owners && idx < cache_ctx->max_entries) {
                if (cache_ctx->slot_owners_lock)
                    pthread_mutex_lock(cache_ctx->slot_owners_lock);

                if (memcmp(&cache_ctx->slot_owners[idx], &expired_keys[i], sizeof(struct cache_key)) == 0) {
                    memset(&cache_ctx->slot_owners[idx], 0, sizeof(struct cache_key));
                    if (cache_ctx->segments.slot_hot) {
                        if (cache_ctx->segments.slot_hot[idx]) {
                            if (cache_ctx->segments.hot_count > 0)
                                cache_ctx->segments.hot_count--;
                        } else if (cache_ctx->segments.cold_count > 0) {
                            cache_ctx->segments.cold_count--;
                        }
                        cache_ctx->segments.slot_hot[idx] = 0;
                    }
                    if (cache_ctx->segments.slot_hit_count)
                        cache_ctx->segments.slot_hit_count[idx] = 0;
                }

                cache_segments_update_metrics(NULL, cache_ctx->metrics, &cache_ctx->segments);

                if (cache_ctx->slot_owners_lock)
                    pthread_mutex_unlock(cache_ctx->slot_owners_lock);
            }
        }
    }

    if (expired_count > 0)
        printf("[Cache] Cleanup: removed %d expired entries\n", expired_count);

    return expired_count;
}
