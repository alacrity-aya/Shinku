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
| PERF-8E-1 | Required decision gate | Pending Query map representation | Bounded `BPF_MAP_TYPE_HASH` with explicit cleanup | `BPF_MAP_TYPE_LRU_HASH` | Use identical Pending ABI and refresh/claim semantics, capacity, packet traces, CPU affinity, compiler flags, and 100 ms/2 s/10 s timeouts under steady misses, bursts over capacity, delayed/lost Responses, retransmissions, duplicate Responses, and adversarial same-key recreation between claim and reclamation. Prove that Claimed reclamation cannot delete a recreated Active record. Report Query-path QPS/p99, TC p99, total CPU including HASH cleanup, correlation success per scenario and in aggregate pressure scenarios, timeout retention, pressure skips/evictions, verifier results, and memory. Adopt LRU only if all correctness/verifier gates pass, aggregate pressure correlation improves by at least 5% relative, each delayed-Response scenario loses at most one percentage point, and Query/TC p99 plus total CPU regress by no more than 5%; otherwise retain HASH. | Implement both equivalent prototypes and complete the measurement before selecting the single production map in 8E. |
| PERF-8E-2 | Deferred optimization | Synchronous versus asynchronous Cache Fill and correlated-event representation | Synchronous callback-local Policy and Store call with fixed 520-byte ring records | Bounded preallocated `FillWork` pool plus single-consumer queue; variable dynptr ring records as an independently attributed representation alternative | Increasing miss/fill rates, 128/512-byte Responses, typical/45 TTL offsets, duplicate Responses that perform speculative fixed-record reservations, ring saturation, Store pressure, and injected slow/failing map operations. Report ring occupancy and consumption, reservation failures, dropped fills, forwarding loss, fill throughput, callback and packet-poll p99, queue depth, pool saturation, CPU, and memory. Attribute fixed-record pressure separately before proposing either variable records or asynchronous Fill. | Synchronous Fill with fixed records remains MVP unless end-to-end evidence shows packet-ring progress or Fill opportunity is materially limited. Test variable records before queueing when representation pressure, rather than callback work, is the measured cause. |
| PERF-M8-1 | Harness implemented and privileged smoke passed; canonical evidence pending; no product pass line | End-to-end cache value | CoreDNS alone with its `cache` plugin omitted/enabled | The same CoreDNS service plus Shinku, including combined native-cache and Shinku cases | Same hot `A/IN` dataset, topology, CPU allocation, warmup, duration, run count, and correctness criteria. Report single-node QPS, p50/p99, DNS-service CPU, Shinku userspace CPU, paired whole-host CPU delta, packet loss, layered Hit ratio, response correctness, dispersion, and complete environment. The frozen Contract and implementation verification are recorded in [Module 8 Performance Evidence Decisions](decisions/module-08-performance-evidence.md). Legacy behavior, harness details, and historical results are not baselines. Incorrect Responses, forwarding loss, or packet-ring starvation fail the correctness/progress gate; other values establish the first new-system baseline. | Execute and record the canonical artifact before declaring Module 8 performance evidence complete. QPS, latency, and CPU have no blocking product threshold until target hardware or an SLO is declared; a low uplift alone does not block the 8E cutover. |

## Result Recording

For each completed item, add:

- result artifact path and commit;
- exact hardware, kernel, compiler, BPF attach mode, topology, and command;
- raw run count and summarized statistics;
- correctness result;
- selected design or explicit decision to retain the baseline;
- follow-up decision or ADR when the result changes architecture.
