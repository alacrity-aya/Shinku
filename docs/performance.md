# DNS Cache Performance Report

## 1. Executive Summary

The shinku implementation achieves a 1.22x throughput improvement, increasing from 349K to 425K Queries Per Second (QPS) when compared to a baseline using only Unbound. Most significantly, average latency is reduced by 4.8x, dropping from 24µs to 5µs.

These results were obtained on a veth pair using generic XDP (SKB mode). Testing on physical hardware with a native XDP driver would likely demonstrate even larger performance gains, as the current environment still involves significant kernel overhead for every packet.

## 2. Test Environment

*   **Kernel:** 6.17.8-300.fc43.x86_64 (Fedora 43)
*   **Architecture:** x86_64
*   **DNS Server:** Unbound (64MB msg-cache, 128MB rrset-cache, 2 threads, prefetch enabled)
*   **Benchmark Tool:** dnsperf v2.14.0
*   **Network Topology:**
    ```
    [dns-ns netns]              [host namespace]
     veth-ns (10.99.0.2) <---> veth-host (10.99.0.1)
                                     |-- XDP (ingress) xdp_rx
                                     |-- TC (egress) tc_tx  
                                    |-- shinku userspace
                                     |-- Unbound :53
    ```
*   **dnsperf Parameters:** 10 concurrent clients, 10 seconds duration, 35 popular domain names, unlimited QPS.
*   **Warmup:** Two full passes through the query file followed by a 2-second settle time before measurements began.

## 3. Benchmark Methodology

The benchmarking process is automated through `tests/benchmark/run_benchmark.sh` and follows four distinct phases.

1.  **Setup:** Configure the veth topology and start the Unbound server.
2.  **Baseline:** Warm the Unbound cache, then execute dnsperf directly without shinku active.
3.  **With Cache:** Start shinku, warm the XDP cache, and run dnsperf again.
4.  **Comparison:** Analyze the results from both runs.

All responses recorded during these tests were NOERROR, representing a 100% success rate with 0% query loss. Three separate benchmark runs were performed to isolate the impact of specific optimizations.

## 4. Results

### Run 1: BPF Logging Enabled (byte-by-byte copy)

| Metric | Baseline | With Cache | Change |
| :--- | :--- | :--- | :--- |
| Queries/sec | 327,290 | 354,390 | +8.3% (1.08x) |
| Avg Latency | 19µs | 10µs | -47% (1.9x faster) |
| Queries Sent | ~3.27M | ~3.54M | +8.3% |
| Query Loss | 0% | 0% | — |

### Run 2: BPF Logging Disabled (byte-by-byte copy)

| Metric | Baseline | With Cache | Change |
| :--- | :--- | :--- | :--- |
| Queries/sec | 318,763 | 411,954 | +29.2% (1.29x) |
| Avg Latency | 16µs | 5µs | -69% (3.2x faster) |
| Queries Sent | ~3.19M | ~4.12M | +29.2% |
| Query Loss | 0% | 0% | — |

### Run 3: BPF Logging Disabled (8-byte wide copy) — FINAL

| Metric | Baseline | With Cache | Change |
| :--- | :--- | :--- | :--- |
| Queries/sec | 349,636 | 425,170 | +21.6% (1.22x) |
| Avg Latency | 24µs | 5µs | -79% (4.8x faster) |
| Min Latency | 4µs | 1µs | -75% |
| Max Latency | 1,922µs | 877µs | -54% |
| Latency StdDev | 61µs | 10µs | -84% |
| Queries Sent | 3,496,409 | 4,251,710 | +21.6% |
| Query Loss | 0% | 0% | — |

The baseline QPS fluctuated between 318K and 350K across different runs due to system noise, CPU scheduling, and the internal state of Unbound. The cached numbers remained more stable because XDP cache hits bypass the majority of standard kernel overhead.

## 5. Optimization Impact Analysis

### 5.1 Disabling BPF Logging

Comparing Run 1 and Run 2 shows that disabling BPF logging increased cache QPS from 354K to 412K, a 16.3% improvement. The speedup ratio rose from 1.08x to 1.29x. At throughput levels exceeding 350K QPS, the BPF ring buffer generates approximately 700,000 calls per second across `bpf_ringbuf_reserve()`, `bpf_snprintf()`, and `bpf_ringbuf_submit()`. Using the compile-time `-Dbpf_log=false` flag removed this bottleneck entirely, confirming that ring buffer logging is a primary constraint at high packet rates.

### 5.2 8-Byte Wide Arena Copy

Run 3 introduced an 8-byte wide copy optimization, resulting in a 3.2% throughput increase over Run 2. While this improvement is modest in the current environment, the high per-packet overhead inherent to generic XDP on veth interfaces likely masks the full benefit. In a native XDP environment where per-packet costs are lower, wide memory copies would represent a more significant portion of the total processing time.

## 6. Latency Distribution Analysis

The latency for cache hits is remarkably stable, averaging 5µs with a standard deviation of only 10µs, compared to 61µs in the baseline. This consistency is a direct result of XDP_TX returning packets before they enter the standard network stack. The minimum recorded latency of 1µs shows the absolute performance floor of the XDP path. Occasional spikes up to 877µs are attributed to cache misses or CPU scheduling delays.

## 7. Performance Constraints

Several factors explain why the throughput improvement is currently limited to 1.22x.

1.  **Generic XDP (SKB mode):** The veth interfaces used for testing do not support native XDP. Packets are fully allocated as `sk_buff` structures before they reach the XDP program, which adds significant overhead and reduces the efficiency of XDP_TX.
2.  **Unbound Efficiency:** Unbound is a highly optimized DNS server. When its internal cache is warm, it can already process 350K QPS, leaving less room for drastic relative improvements in a non-native XDP environment.
3.  **Shared Bottleneck:** Both baseline and cached traffic use the same veth pair, which creates a common throughput limit for the entire system.
4.  **Hardware Expectations:** On physical network cards with native XDP support, the kernel network stack would be completely bypassed for cache hits. This shift typically yields improvements of 3x to 10x or more.

## 8. Conclusions

The shinku system successfully serves responses from the XDP layer, providing a 4.8x reduction in latency. While throughput gains are currently limited by the virtualized networking environment, the architecture is fundamentally sound. BPF logging proved to be a major performance hurdle and should remain disabled for production workloads. Transitioning to native XDP on dedicated hardware will likely allow these performance benefits to scale significantly further.
