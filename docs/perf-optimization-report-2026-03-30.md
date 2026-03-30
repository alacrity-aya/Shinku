# Performance Optimization Report (P0 + P1)

Date: 2026-03-30

## Scope

This report covers implementation and validation for the requested P0/P1 optimizations:

- P0
  - remove O(N) segment-metrics scans from cache insert/cleanup path
  - reduce redundant DNS name parsing in userspace parser hot path
  - reduce cleanup-path per-key overhead in expiry pass
- P1
  - reduce admission path overhead (recent-insert checks and repeated computations)

## Implemented Optimizations

### 1) Incremental hot/cold segment counters (P0)

Files:

- `src/core/cache_types.h`
- `src/core/cache_ops.c`
- `src/core/loader.c`

Changes:

- Added `hot_segment_count` and `cold_segment_count` to `cache_context`.
- Replaced `update_segment_metrics()` full-slot scan with direct export of maintained counters.
- Added counter adjustment logic on:
  - insert into empty slot
  - replace distinct key
  - same-key rehit promotion (cold -> hot)
  - cleanup deletion of expired slot

Effect:

- Removes O(max_entries) scan from every insert and cleanup update.

### 2) One-pass DNS name parse primitive (P0)

Files:

- `src/core/dns_parser.c`
- `src/core/dns_parser.h`
- `tests/unit/hash/dns_hash_test.c`

Changes:

- Added `dns_parser_parse_name_impl(...)` that can return in one traversal:
  - normalized hash
  - flattened name
  - consumed wire length
- Rewired existing public wrappers:
  - `dns_parser_calculate_hash_strict_impl` now delegates to one-pass primitive
  - `dns_parser_flatten_name_impl` now delegates to one-pass primitive
- In `dns_parser_handle_event`, answer-section owner name handling now parses once per RR for both flatten + consumed length, replacing separate `flatten_name + skip_name` steps.

Effect:

- Reduces repeated label traversal and branch work in parser hot path.

### 3) Cleanup loop reuse of looked-up values (P0)

File:

- `src/core/cache_ops.c`

Changes:

- During initial map walk, when key is expired, store both key and `cache_value` in temporary batch arrays.
- In delete phase, use stored `arena_idx` directly instead of performing a second `bpf_map_lookup_elem` per expired key.

Effect:

- Reduces syscall/load overhead for expired entries in cleanup pass.

### 4) Recent-insert dampening fast-path via bucketed lookup (P1)

File:

- `src/core/cache_ops.c`

Changes:

- Replaced full linear scan over `recent_insert_cap` for each check with a fixed-size bucketed probe:
  - compute key fingerprint
  - probe only two slots in its bucket
- `track_recent_insert` now updates same small bucket (existing key / empty slot / oldest slot replacement).

Effect:

- reduces recent-insert lookup from O(cap) to O(1) bounded probe.

## Benchmarks

Binary:

- `build-dev2/tests/unit/dns_bench`

Command run:

- `sudo ./tests/unit/dns_bench` (from `build-dev2`)

### Result Highlights

1. **Name parse legacy vs optimized (A/B in same binary)**

- Legacy path (hash + flatten + skip): **67.8 ns/op**
- Optimized one-pass path: **30.2 ns/op**
- **Speedup: 2.25x**

2. **Recent lookup legacy scan vs optimized buckets (A/B in same binary)**

- Legacy linear scan: **104871.8 ns/op**
- Optimized bucket probe: **10.454 ns/op**
- **Speedup: 10032.07x**

3. Additional parser throughput sanity metric

- Parse throughput (A record, no store): **179.5 ns/op**

Notes:

- Cache-store throughput benchmark remained available and passes under root.
- The A/B microbenchmarks were intentionally added to compare old-vs-new logic directly in the same executable/run style.

## Correctness Validation

### Unit / sanitizer tests

Executed and passing:

- `meson compile -C build-dev2`
- `meson compile -C build-asan`
- `meson compile -C build-tsan`
- `meson test -C build-dev2 "DNS Hash Consistency Check"`
- `meson test -C build-dev2 "DNS Parser Test"`
- `meson test -C build-dev2 "Observability HTTP Test"`
- `meson test -C build-asan "DNS Parser Test"`
- `meson test -C build-tsan "DNS Parser Test"`
- `meson test -C build-asan "DNS Hash Consistency Check"`
- `meson test -C build-tsan "DNS Hash Consistency Check"`
- `sudo meson test -C build-dev2 "Cache Store Correctness Test"`
- `sudo meson test -C build-asan "Cache Store Correctness Test"`
- `sudo meson test -C build-tsan "Cache Store Correctness Test"`

### Integration

Executed and passing:

- `sudo python3 tests/integration/test_dns_cache.py -v`
  - 23 passed, 3 skipped (ECS-disabled profile), runtime ~46.7s

### New/updated correctness checks

- Added parser-combo consistency test in hash suite:
  - `dns_parser_parse_name_impl` output hash/consumed/flat length is consistent with legacy helper outputs.
- Added incremental segment-counter test in cache suite:
  - verifies hot/cold counter behavior through first insert, rehit, and subsequent insert.

## Trade-offs and Decisions

1. **Batch BPF cleanup ops**

- Research indicates `bpf_map_lookup_batch`/`bpf_map_lookup_and_delete_batch` can reduce syscall count on large maps.
- Not introduced in this patch set to keep compatibility/risk low and avoid larger control-flow changes during correctness-sensitive optimization pass.
- Current cleanup optimization still reduces one lookup per expired key.

2. **Segment counters as source of truth**

- Changed from recompute-by-scan to maintained counters.
- This requires careful updates on every state transition; dedicated tests added to protect this invariant.

## Summary

P0/P1 optimizations were implemented and validated with tests + benchmarks.

Observed measured gains in direct A/B microbenchmarks:

- one-pass parser name handling: **~2.25x faster**
- recent-insert admission lookup: **orders-of-magnitude faster** under large-cap synthetic scenario

Functional correctness remains validated by unit, sanitizer, and integration coverage.
