// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file obs_bpf_metrics.h
 * @brief BPF-side metric identifiers.
 *
 * These metric IDs correspond to counters maintained in BPF programs
 * and synchronized to userspace via a per-CPU array map. The counters
 * are sampled by userspace for Prometheus export.
 */

/**
 * @enum obs_bpf_metric_id
 * @brief Identifiers for BPF-side performance counters.
 */
enum obs_bpf_metric_id {
    OBS_BPF_CACHE_HIT = 0,         /**< Cache hit: response served from XDP cache */
    OBS_BPF_CACHE_MISS = 1,        /**< Cache miss: forwarded to upstream */
    OBS_BPF_CACHE_EXPIRED = 2,     /**< Cache entry expired during lookup */
    OBS_BPF_CACHE_GEN_MISMATCH = 3, /**< Generation mismatch (slot reused) */
    OBS_BPF_CACHE_SEQ_CONFLICT = 4, /**< Seqlock conflict during read */
    OBS_BPF_XDP_TX = 5,            /**< XDP_TX action (response transmitted) */
    OBS_BPF_TC_RINGBUF_DROP = 6,   /**< Ring buffer submission dropped */
    OBS_BPF_TC_CAPTURE = 7,        /**< DNS packet captured to ring buffer */
    OBS_BPF_METRIC_MAX = 8,        /**< Sentinel: number of BPF metrics */
};