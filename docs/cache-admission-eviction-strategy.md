# Cache Admission and Eviction Strategy Proposal

## Context

Current cache replacement is ring-slot overwrite with TTL cleanup. This is fast and simple, but under high-cardinality/random-subdomain pressure it can evict hot entries too aggressively and reduce effective protection of upstream resolvers.

## Problem Statement

The current policy behaves like FIFO-by-slot under sustained churn:

- every accepted response eventually overwrites an older slot,
- low-value one-off names can displace high-reuse hot keys,
- random-subdomain floods can force cache miss ratio toward 100% and shift load upstream.

This is especially visible when attackers generate unique labels (water-torture style) or when workloads naturally have large long-tail cardinality.

## Goals

1. Preserve hot-key residency under churn.
2. Keep XDP lookup path simple and predictable.
3. Keep memory and lock overhead bounded.
4. Maintain correctness and anti-pollution constraints (ECS/negative cache semantics).

## Non-Goals

- Replacing the BPF hash lookup path with complex per-packet adaptive logic.
- Introducing heavy probabilistic structures in BPF hot path.

## Recommended Direction (Phased)

### Phase A: Low-risk admission guardrails (userspace-only)

Implement admission filters before cache insert:

- **Minimum TTL threshold for positive entries**
  - Reject caching entries below a configurable `min_cache_ttl` except negative cache policy cases.
- **Per-name short-window insert dampening**
  - If a key was inserted recently, suppress re-insert churn unless response materially differs.
- **Burst-aware optional skip mode**
  - Under detected high-cardinality pressure, sample/cache only a subset of new cold keys.

Expected impact: immediate churn reduction with minimal complexity.

### Phase B: Segmented residency (hot/cold queues in userspace metadata)

Maintain lightweight metadata side-table in userspace:

- New keys enter **cold segment**.
- Re-hit keys are promoted to **hot segment**.
- Overwrite preference evicts cold first when possible.

Implementation detail:

- Keep BPF map schema unchanged for lookup speed.
- Use userspace slot-owner metadata to bias slot selection during `cache_store_response_with_flags`.

Expected impact: protects hot keys from one-off churn.

### Phase C: Approximate frequency-aware admission (TinyLFU-inspired)

Add a bounded approximate frequency sketch in userspace:

- Estimate candidate frequency versus victim frequency.
- Admit candidate only if estimated utility is higher.

This should remain userspace-side only; BPF stays exact-match + fast lookup.

Expected impact: strong resilience against random unique-key floods.

## Transport/Fallback Interaction

With cached `TC=1` responses enabled, admission policy should include dedicated handling:

- truncated fallback entries are useful shielding artifacts and should not be treated as low-value noise,
- but they should have bounded TTL and optional cap to avoid dominating cache space.

## Negative Cache Interaction

- Keep existing RFC2308-style bounded negative TTL behavior.
- Apply stricter admission caps for negative entries under random-subdomain attack patterns.
- Consider per-zone negative cache quotas to prevent hostile zone dominance.

## Metrics to Add (for safe rollout)

- `shinku_cache_admission_attempt_total`
- `shinku_cache_admission_accept_total{reason=...}`
- `shinku_cache_admission_reject_total{reason=...}`
- `shinku_cache_hot_segment_size`
- `shinku_cache_cold_segment_size`
- `shinku_cache_eviction_total{segment=hot|cold,reason=...}`

## Rollout Plan

1. Add Phase A behind runtime config flags, default conservative.
2. Validate with benchmark workloads:
   - baseline hot-cache,
   - mixed-hit,
   - wraparound-pressure,
   - random-subdomain synthetic dataset.
3. Add Phase B only after metrics show clear admission-side gains.
4. Add Phase C only if Phase A/B are insufficient under stress.

## Validation Scenarios

1. **Hot-key preservation test**: stable popular domains should keep high hit ratio under injected long-tail noise.
2. **Random-subdomain pressure test**: miss amplification should be measurably reduced versus ring-only baseline.
3. **TC fallback test**: repeated UDP queries to large-answer domains should avoid repeated upstream UDP effort.
4. **ECS isolation test**: admission/eviction changes must not break ECS partition correctness.

## Tradeoff Summary

- Ring overwrite only: simplest, weakest under cardinality pressure.
- Segmented hot/cold: moderate complexity, strong practical gains.
- TinyLFU-like admission: best protection potential, highest implementation complexity.

Recommended immediate action: implement Phase A, prepare Phase B metadata hooks, keep BPF hot path unchanged.

## Design Q&A (implementation-level)

### 1) How to know a key was inserted recently? Will it add overhead?

Use a userspace-side fixed-size metadata table keyed by `cache_key` hash:

- store `last_insert_ns` and a compact rolling insert counter,
- update only on successful insert path,
- compare `now_ns - last_insert_ns` against a dampening window.

Overhead profile:

- no new syscalls per packet,
- one extra userspace hash-table probe/update per accepted response,
- no XDP hot-path cost.

### 2) What should the bounded approximate sketch look like?

For TinyLFU-like admission, start with Count-Min Sketch in userspace:

- structure: `d` rows × `w` counters (e.g., 4 × 4096, `uint16_t` counters),
- key update increments one counter per row via independent hash seeds,
- estimate is min across rows,
- periodic aging by right-shift/decay over all counters at fixed interval.

This is bounded, cache-friendly, and does not require per-key heap objects.

### 3) How to decide a key is "cold"?

A key is cold when it fails one or more admission thresholds:

- low sketch frequency estimate versus victim estimate,
- no short-window re-hit (single-shot insertion pattern),
- optional low TTL + no observed repeat access.

Practical decision rule:

- if `freq(candidate) <= freq(victim)` and candidate is first-seen in dampening window,
  reject candidate under pressure mode.

### 4) Will this introduce new syscalls and reduce performance?

Not if implemented as proposed:

- admission/eviction metadata lives in existing userspace process memory,
- operations piggyback on current response-ingest path,
- no extra syscall needed for sketch maintenance itself,
- map syscalls remain the same class as current insert/update/delete flow.

Only optional future telemetry export may add periodic work, not per-packet syscall amplification.
