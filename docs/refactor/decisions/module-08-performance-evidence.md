# Module 8 Performance Evidence Decisions

This file records the frozen design for `PERF-M8-1`. It refines the required evidence in `benchmark-backlog.md`
without introducing a product performance pass line.

Status: design frozen and harness implemented on 2026-08-03; privileged smoke passed on 2026-08-05. Canonical
evidence is a deferred TODO while Module 9 is active; it remains required before Module 8 performance evidence is
considered complete.
If an implementation-time tool or kernel fact makes a frozen decision infeasible, reopen only that decision with
recorded evidence rather than silently changing the measurement Contract.

Implementation lives in `tests/benchmark/perf_m8_lib.py`, `perf_m8_worker.py`, and `run_perf_m8.py`, with focused
unprivileged tests in `perf_m8_test.py`. The harness builds `build-perf/shinku_bench` and the pinned CoreDNS source,
generates deterministic workloads/configs, performs preflight and capability probes before topology creation, then
hands the complete run to one privileged worker. The worker owns topology and process cleanup and writes raw interval
artifacts plus aggregate JSON and Markdown reports.
For local use, `scripts/run-perf-m8.sh` prepares or reuses a JSON-capable dnsperf and invokes the smoke or full
mode; `--canonical` leaves out the dirty-worktree override.

## Benchmark Contract

1. Run on the current development host using the integration veth topology and production native/driver XDP attach.
2. Use host processes rather than Docker. CoreDNS is the DNS Service under test; a separate local dnsmasq instance is
   its deterministic no-cache upstream and returns one unique `A` record per name with TTL 300 seconds. CoreDNS
   native-cache-off omits the `cache` plugin; native-cache-on enables it. This supersedes the earlier Unbound choice:
   zero-sized Unbound caches lower downstream TTL to zero and are incompatible with Shinku admission, while
   `forward-no-cache` is less explicit than CoreDNS's optional cache boundary.
3. Run `ceiling` with one hot name and `hotset` with 4,096 names drawn from Zipf `s=1.1`. The hotset trace contains
   1,048,576 queries from a fixed seed. Generator overrides are allowed but make the result non-canonical; archive its
   hash and statistics rather than the generated trace.
4. Compare four scenarios for each workload: CoreDNS cache off/on, and each of those with Shinku enabled. Capacity uses
   unlimited offered load with the scenario's own zero-loss calibration. Common load is 80% of the lowest median
   capacity observed for that workload and uses that slowest scenario's calibrated clients/outstanding unchanged for
   all four scenarios.
5. Pin dnsperf to CPUs `0,2`, CoreDNS to `4,6`, Shinku userspace to `8`, dnsmasq to `10`, and sampling to E-core `12`.
   Do not alter the governor or cpusets.
6. Canonical defaults are five rounds, 5-second warmup, 30-second measurement, and fixed-seed randomized scenario
   order. CLI overrides are supported but non-canonical. Provide an explicit smoke preset.
7. Calibrate every workload/scenario pair for five seconds with two threads across clients
   `1,4,10,20,40,80,160,320,512` and outstanding `100,1000,4096`. Select the smallest zero-loss configuration within
   98% of the observed maximum; a boundary optimum invalidates calibration. The original client grid ended at 20 and
   calibrated only the Shinku/native-cache-off scenario. The privileged 2026-08-05 development run selected
   clients 20/outstanding 1000 as its sole zero-loss candidate within 98% of the 684,754 QPS observed maximum, so that
   grid did not enclose the host's optimum. The first extension through 80 clients also selected its upper boundary at
   704,957 QPS. Decision 7 was reopened on that implementation evidence and extended through dnsperf 2.15.0's native
   two-thread limit of 512 clients (256 sockets per thread); the selection and boundary rules are unchanged. Selecting
   512 therefore invalidates calibration rather than silently accepting a tool-limited optimum. A later development
   run proved that reusing the fast Shinku scenario's 160/1000 selection overloaded the CoreDNS-only capacity scenario:
   it lost 9,560 of 2,952,316 queries while its DNS correctness and forwarding metrics remained valid. Decision 7 was
   therefore also amended to calibrate each scenario independently; decision 4 preserves one common-load driver shape.
8. Wait up to 120 seconds for package temperature at or below 60 C. Capacity-QPS coefficient of variation must be at
   most 5%; otherwise retain all rounds and mark the run unstable/incomplete rather than discarding outliers.

## Measurement And Correctness

9. Archive dnsperf JSON `latency-histogram`. Report QPS as the median of per-round values, merged-histogram p50/p99
   using bin upper bounds, and the range of per-round percentiles.
10. Record CoreDNS PID CPU, Shinku PID CPU, per-CPU and whole-host CPU. Report BPF CPU only as a derived same-round
    paired host delta, never as PID-attributed CPU.
11. Derive hit ratio from dnsperf sent count plus CoreDNS request/cache counters. With the cache plugin omitted,
    native-cache hits are defined as zero; dnsmasq upstream queries provide a cross-check. Do not add BPF counters.
12. Validate every unique answer before and after each scenario. The formal interval requires completed equals sent,
    zero loss, NOERROR responses, and no DNS-service drops or timeouts. Run a separate pre/post Miss-to-Fill-to-Hit
    sentinel to prove packet-ring progress.
13. Preserve the production TCX-to-legacy-TC fallback, record the actual mode, and require it to remain constant. Record
    existing offload settings. `--disable-offloads` is available but untested and non-canonical.

## Harness And Evidence

14. Build Shinku in dedicated `build-perf/` release mode with `-O3`, sanitizers and BPF logging disabled. Use
    `tests/benchmark/run_perf_m8.py`, separate from `scripts/run-tests.py`.
15. Canonical runs require a clean commit and automatically run `./scripts/run-tests.py check --fail-fast`. Skipping
    correctness or smoke is non-canonical. `--allow-dirty` records HEAD, diff, and untracked metadata and is
    non-canonical.
16. Extend `tests/integration/topology.py` to accept an XDP pass object; the benchmark uses
    `build-perf/xdp_pass.bpf.o`. Use an ordinary orchestrator with one sudo privileged worker.
17. Reuse one topology for a run but restart processes for every scenario. After each Shinku scenario, verify that host
    XDP and TC are detached. Refuse startup if the namespace, interfaces, or hooks already exist; never remove unknown
    resources.
18. Interrupted runs remain incomplete and cannot resume. Start a new run ID. Keep transient results under ignored
   `tests/benchmark/results/<run-id>/`; publish canonical evidence under
   `docs/performance/perf-m8-1-<date>/` with report, manifest, summary, raw outputs, and generated configs. Replace the
   legacy `docs/performance.md`. The worker prints weighted calibration/scenario progress, elapsed time, and estimated
   remaining time to stderr only between timed operations. SIGINT records an incomplete `KeyboardInterrupt` result,
   reports cleanup progress without a Python traceback, tears down owned services/topology, and exits with status 130.
19. Use Shinku cache capacity 16,384, response limit 512, Pending capacity 8,192, Pending timeout 2 seconds, and cleanup
    interval 10 seconds.
20. Configure CoreDNS native-cache-on as `cache 300` with `success 16384 300 0` and `servfail 0`. Matching Shinku's
    16,384-entry capacity keeps capacity differences out of the primary comparison; the extra headroom over the
    4,096-name hotset also prevents CoreDNS's 256 independently filled shards from causing premature random eviction.
    Native-cache-off omits the `cache` plugin entirely.
21. Canonical runs build CoreDNS from a clean `ref/coredns` checkout at commit
    `76056dd2e56f04d1c1984160f54098e403fbb718`, using the local Go toolchain, `CGO_ENABLED=0`, and `-trimpath`, with
    output under `build-perf/tools/`. Record the CoreDNS commit and source status, Go version, `go.sum` hash, complete
    build arguments, and binary hash. `--coredns-source` may select another checkout, but a different path or commit is
    non-canonical. The harness does not install a system package or clone/download third-party source.
22. For each formal interval let `S` be dnsperf sent queries, `Q` CoreDNS received queries, `H` CoreDNS native-cache
    hits, and `U` completed CoreDNS forwards to dnsmasq. Report Shinku contribution `(S-Q)/S`, CoreDNS contribution `H/S`, total
    end-to-end hit ratio `(S-Q+H)/S`, and CoreDNS-local hit ratio `H/Q` (`N/A` when `Q` is zero). Require
    `0 <= H <= Q <= S` and `U == Q-H`; a violation invalidates the round. Native-cache-off defines `H` as zero because
    the cache plugin is absent. This decomposition relies on the formal zero-loss correctness gate and adds no BPF
    counters.
23. Run CoreDNS under `taskset -c 4,6` with `GOMAXPROCS=2` and the Corefile directive `multisocket 2`. This fixes Go
    execution parallelism and creates two `SO_REUSEPORT` listeners so a single receive socket does not become the
    ceiling bottleneck. Record the requested and observed affinity and environment. Runtime helper threads remain part
    of CoreDNS PID CPU and cannot execute outside the assigned CPUs.
24. Derive `U` from the interval delta of the sum of
    `coredns_proxy_request_duration_seconds_count{proxy_name="forward",to="<dnsmasq>"}` across RCODE labels. Do not
    enable dnsmasq per-query logging or add nftables/BPF packet counters: both would alter the cache-miss path. Require
    all forward completions to be NOERROR in addition to `U == Q-H`; forward timeout/error and dnsperf loss remain
    independent correctness failures.
25. Warm each fresh scenario with the same workload for five seconds in a separate dnsperf process. Preserve the
    naturally formed CoreDNS/Shinku cache state, then restart the formal trace from its first query without restarting
    services. Do not prefill every unique name. Record warmup sent/completed and ending CoreDNS cache entries only as
    diagnostics; exclude them from formal aggregation. Calibration uses separate process instances, and each scenario
    occurrence remains shorter than the 300-second TTL.
26. Enable the minimal CoreDNS `prometheus` plugin without `runtime_metrics`. After warmup, scrape and archive raw
    pre-interval metrics, then read the CPU baseline; after dnsperf completes, read final CPU before scraping and
    archiving post-interval metrics. Do not scrape during the formal interval. This excludes exposition serialization
    from measured CoreDNS CPU while retaining required per-query counter updates.
27. Sample CoreDNS PID, Shinku PID, assigned per-CPU, and whole-host `/proc` counters once per second from sampler CPU
    `12`, scheduled against absolute `CLOCK_MONOTONIC` deadlines. Save actual timestamps and missed/late samples for
    diagnostics. Formal CPU aggregates always use exact pre/post counter deltas rather than summing samples.
28. For every measured process report raw CPU-seconds, mean cores (`cpu_seconds / wall_seconds`), and assigned-capacity
    utilization (`mean_cores / assigned_cpu_count`). Use mean cores as the primary comparison. Report per-CPU busy
    percentages separately. Name Shinku process fields `shinku_userspace_*`; never include kernel work in PID CPU.
29. Do not report a derived BPF CPU value. Pair each Shinku scenario with the same-round, same-workload/load, same-native-
    cache scenario and report only `paired_whole_host_delta`. This whole-system effect includes BPF and kernel-path cost,
    Shinku userspace, and reduced CoreDNS/dnsmasq work, so it may legitimately be negative and cannot be decomposed by
    subtracting PID counters. Independent BPF profiling is outside `PERF-M8-1`.
30. Accept any dnsperf version whose pre-topology capability probe proves streaming JSON plus
    `statistics.latency.histogram` bins; do not parse legacy text as a fallback. Record the reported version, package,
    resolved binary path, binary hash, and full command. A failed probe aborts before privileged setup. The current
    development host's packaged `/usr/bin/dnsperf` reports 2.15.0 but was built without `-j`; the capability probe
    rejects it. `--dnsperf-binary` accepts a JSON-capable build and records its package ownership and binary hash.
31. Run CoreDNS, dnsmasq, and Shinku only as host processes. Do not implement a Docker runner for `PERF-M8-1`.
    Docker bridge/port-publish changes the miss path with container veth, bridge, NAT, and netfilter while XDP hits
    return earlier, invalidating the fixed topology. Host-network containers avoid that data-plane change but still add
    a second untested PID/cgroup/image lifecycle for no MVP benefit. Record the already-running Docker daemon version
    and state as environment metadata only.
32. Enforce the 60 C gate using the hwmon device named `coretemp` and sensor label `Package id 0`, not an unstable
    `hwmonN` path. The current host exposes one such package sensor. A missing or ambiguous package sensor fails a
    canonical run; do not substitute DIMM, NVMe, Wi-Fi, or per-core temperature.
33. Preflight the physical topology behind the configured logical CPUs. The canonical allocation currently places
    dnsperf, CoreDNS, Shinku, and dnsmasq on distinct P-cores and the sampler on a non-SMT E-core. Require role sibling
    sets not to overlap and record all sibling activity. Consistent with the earlier noise decision, do not offline or
    cpuset-isolate unused SMT siblings.

## Implementation Verification

Completed without privilege:

- `python3 tests/benchmark/perf_m8_test.py -v`: 9 tests passed.
- `python3 -m py_compile tests/benchmark/*.py tests/integration/topology.py`: passed.
- `meson compile -C build-perf shinku_bench xdp_pass.bpf.o`: passed.
- `./scripts/run-tests.py quick --fail-fast`: 10 Host tests passed.
- The pinned CoreDNS checkout and JSON-capable dnsperf capability probe passed; a loopback CoreDNS/dnsmasq check
  confirmed `U == Q-H` for the emitted Prometheus metrics.

The privileged root topology smoke passed on 2026-08-05, including real XDP/legacy-TC attachment, hook-mode detection,
namespace traffic, Miss-to-Fill-to-Hit sentinels, service teardown, and hook cleanup. Canonical evidence is deferred as
a TODO until the DPDK work reaches a stable comparison point.

## Freeze Boundary

All known decisions that affect workload semantics, topology, process placement, measurement, correctness,
aggregation, reproducibility, and evidence ownership are resolved. Code organization details may be selected during
implementation only when they do not change this Contract. Docker support, CI design, independent BPF CPU attribution,
and a general-purpose benchmark framework remain outside `PERF-M8-1`.
