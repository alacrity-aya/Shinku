// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

enum obs_bpf_metric_id {
    OBS_BPF_CACHE_HIT = 0,
    OBS_BPF_CACHE_MISS = 1,
    OBS_BPF_CACHE_EXPIRED = 2,
    OBS_BPF_CACHE_GEN_MISMATCH = 3,
    OBS_BPF_CACHE_SEQ_CONFLICT = 4,
    OBS_BPF_XDP_TX = 5,
    OBS_BPF_TC_RINGBUF_DROP = 6,
    OBS_BPF_TC_CAPTURE = 7,
    OBS_BPF_METRIC_MAX = 8,
};
