# Refactor Benchmark Backlog

Purpose:

- Record design choices that need measured evidence rather than intuition.
- Separate benchmarks required to complete an active module from post-MVP optimization experiments.
- Fix the workload, metrics, correctness gates, and decision rule before collecting results.

This file is a decision backlog, not a performance report. Completed measurements and environment details belong in `docs/performance.md` or a linked result artifact. A benchmark result may change an implementation choice only after its correctness suite passes unchanged.

## Measurement Rules

- Compare alternatives on the same machine, kernel, BPF compiler flags, map capacities, response-size distribution, CPU affinity, and logging configuration.
- Include warmup and enough repeated runs to report median, p99, dispersion, and run-to-run stability; do not decide from one run.
- Measure the complete cost moved by an alternative. For example, cleanup comparisons include Store lock wait and cleanup CPU, while Pending map comparisons include explicit-cleanup CPU.
- Record throughput and latency together. A throughput gain does not justify a material p99 regression on the target hot `A/IN` workload.
- Require identical correctness outcomes, loss behavior, Cache Capacity, and Fail-open behavior before comparing performance.
- Set a numerical adoption threshold before executing each benchmark. Results inside the noise band retain the simpler MVP design.

## Module 8 Backlog

| ID | Status | Decision | MVP baseline | Alternatives | Required workload and metrics | Decision timing |
|---|---|---|---|---|---|---|
| PERF-8D-1 | Deferred optimization | Store Admission and victim selection | Free-list followed by deterministic round-robin | Bounded CLOCK; a deliberately specified TinyLFU-style policy | Hot Zipfian `A/IN`, mixed hot/cold, scan pollution, working set below/at/above capacity, and TTL churn. Report Cache Hit ratio, Store throughput, p99 fill latency, DNS-service QPS/CPU, eviction counts, and metadata memory. | Not an 8D completion blocker. Reopen only when the round-robin baseline has end-to-end results. |
| PERF-8D-2 | Deferred optimization | Store/cleanup synchronization | One Store-owned mutex | Global metadata plus per-slot locks; another concrete synchronization design justified by profiling | One fill caller plus one cleanup caller at several capacities, cleanup batch sizes, miss rates, and expiration bursts. Report fill throughput, callback p99, mutex wait/hold time, cleanup completion time, CPU, and starvation. | Not an 8D completion blocker. Reopen only if lock contention is measurable in the production-shaped benchmark. |
| PERF-8D-3 | Deferred optimization | Expiration cleanup representation | Owner-index sweep with persistent bounded cursor | Userspace expiration min-heap with generation-filtered stale nodes | Capacities from small test sizes through the supported maximum; short/uniform/long and bimodal TTL distributions; low and high update churn. Report cleanup CPU, slots or heap nodes examined, Store p99 while cleanup runs, memory, expired resident duration, and total sweep/reclamation time. | Implement and instrument the sweep in 8D; comparison with the heap is not an 8D completion blocker. |
| PERF-8D-4 | Deferred optimization | XDP coherent snapshot | Per-CPU scratch snapshot after arena seqlock read | Immutable copy-on-write slots with a fully specified per-CPU QSBR reclamation protocol | Response sizes 128/256/512, TTL plans 1/typical/45, hot single-key and distributed-key traffic, and concurrent same-key Update. Report XDP QPS, p50/p99, cycles or instructions per hit, scratch-map cost, seqlock conflicts, and memory. | Reopen only if the safe scratch path is a measured hot-path bottleneck; QSBR is not part of the MVP. |
| PERF-8E-1 | Required decision gate | Pending Query map representation | None until comparison | `BPF_MAP_TYPE_LRU_HASH`; bounded `BPF_MAP_TYPE_HASH` with explicit cleanup | Identical capacity and timeout under steady misses, burst over capacity, delayed Responses, lost Responses, retransmissions, and duplicate Responses. Report Query-path QPS/p99, TC p99, cleanup CPU, correlation success, timeout retention, pressure skips/evictions, and memory. | Must complete before selecting the 8E Pending map. |
| PERF-8E-2 | Deferred optimization | Synchronous versus asynchronous Cache Fill | Synchronous callback-local Policy and Store call | Bounded preallocated `FillWork` pool plus single-consumer queue | Increasing miss/fill rates, 128/512-byte Responses, typical/45 TTL offsets, Store pressure, and injected slow/failing map operations. Report ring consumption, dropped fills, forwarding loss, fill throughput, callback p99, queue depth, pool saturation, CPU, and memory. | Synchronous Fill remains MVP unless end-to-end evidence shows it limits packet-ring progress materially. |
| PERF-M8-1 | Module completion evidence | End-to-end cache value | DNS service alone with native cache on/off | Same service plus Shinku, including combined native-cache and Shinku case | Same hot `A/IN` dataset, topology, CPU allocation, warmup, duration, and success criteria. Report single-node QPS, p50/p99, DNS-service CPU, Shinku CPU, packet loss, hit ratio, and response correctness. | Required before declaring Module 8 performance goals demonstrated; it does not replace correctness tests. |

## Result Recording

For each completed item, add:

- result artifact path and commit;
- exact hardware, kernel, compiler, BPF attach mode, topology, and command;
- raw run count and summarized statistics;
- correctness result;
- selected design or explicit decision to retain the baseline;
- follow-up decision or ADR when the result changes architecture.
