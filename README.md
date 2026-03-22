# Shinku

<p align="center">
  <img src="asserts/CG.avif" alt="Shinku" width="600">
</p>

An eBPF-based DNS caching proxy that serves cached responses at the XDP layer for near-line-rate performance.

## Key Features

*   XDP fast path: Cache hits are served via XDP_TX directly, bypassing the kernel network stack.
*   BPF Arena memory: Shared memory between XDP programs and userspace, requiring Linux 6.9 or newer.
*   Transparent proxy: Operates in front of any DNS server without requiring configuration changes.
*   VLAN support: Capable of parsing Q-in-Q (802.1Q and 802.1AD) tags.
*   EDNS Client Subnet (ECS) aware: Implements a scope-zero strategy for global caching efficiency.
*   Zero-copy arena reads: Uses 8-byte wide copies from arena memory within the XDP hot path.
*   Conditional BPF logging: Includes a compile-time flag to remove logging overhead in production environments.

## Architecture Overview

The system uses a 3-layer design to process DNS traffic:

1.  XDP program (xdp_rx): Handles ingress traffic. It parses DNS queries, performs cache lookups, and serves cached responses using XDP_TX.
2.  TC program (tc_tx): Handles egress traffic. It captures DNS responses destined for clients and forwards them to userspace via a ring buffer.
3.  Userspace (shinku): Receives responses from the ring buffer, validates and decompresses them, then stores the data into the BPF arena and cache_map.

```text
       +----------+         +----------+         +------------+
       |          |  query  |  XDP_RX  |  query  |            |
       |  Client  +-------->+ (Ingress)+-------->+ DNS Server |
       |          |         +----+-----+         |            |
       |          |              |               |            |
       |          |  reply  +----+-----+  reply  |            |
       |          |<--------+  TC_TX   |<--------+            |
       +----------+         | (Egress) |         +------------+
                            +----+-----+
                                 |
                        +--------v---------+
                        |    Userspace     |
                        |   (shinku)        |
                        +--------+---------+
                                 |
                        +--------v---------+
                        |    BPF Arena     |
                        |  & cache_map     |
                        +------------------+
```

The BPF Arena and cache_map are shared resources accessed by both the XDP programs and the userspace daemon.

## Requirements

*   Linux kernel 6.9 or newer (for BPF Arena support)
*   Clang/LLVM 18 or newer (for BPF target)
*   Meson build system
*   libbpf, libelf, and zlib
*   c-ares (automatically fetched through meson wrap)
*   Root privileges for attaching XDP and TC programs

## Quick Start

Build the project using Meson:

```bash
meson setup build
meson compile -C build shinku xdp_pass.bpf.o
```

Run the system:

```bash
sudo ./build/shinku -i eth0
```

For development with BPF logging enabled:
```bash
meson setup -Dbpf_log=true build
```

For production without logging overhead:
```bash
meson setup -Dbpf_log=false build
```

## Usage

```text
shinku [OPTIONS]
  -i, --interface IFACE    Network interface to attach (default: lo)
  -l, --log-level LEVEL    Log level: debug, info, warn, error (default: info)
  -a, --arena-pages PAGES  Arena size in pages (default: 2112)
```

Note: When using XDP_TX on veth pairs, load `xdp_pass.bpf.o` on the peer interface to ensure traffic passes correctly.

## Performance

The following results were recorded on a veth pair using generic XDP/SKB mode. Native XDP on physical network interfaces is expected to provide even greater performance gains.

| Metric | Baseline (Unbound) | With shinku | Improvement |
| :--- | :--- | :--- | :--- |
| QPS | 349,636 | 425,170 | 1.22x |
| Avg Latency | 24µs | 5µs | 4.8x |

Detailed methodology and full results are available in `docs/performance.md`.

## Observability

Shinku exposes Prometheus-compatible metrics via HTTP endpoints for monitoring and debugging.

### Endpoints

| Endpoint | Description |
| :--- | :--- |
| `GET /healthz` | Liveness probe — returns `200 OK` with body `ok` |
| `GET /readyz` | Readiness probe — returns `200 OK` when BPF programs attached, `503` otherwise |
| `GET /metrics` | Prometheus text format metrics export |

Default port: `9095` (configurable via `--metrics-port`).

### BPF Metrics (sampled)

These counters are sampled in the XDP/TC hot path using `bpf_get_prandom_u32() & sample_mask == 0`. When `--obs-bpf=0` (default), these are zero.

| Metric | Type | Description |
| :--- | :--- | :--- |
| `shinku_cache_hit_total` | counter | Sampled XDP cache hits |
| `shinku_cache_miss_total` | counter | Sampled XDP cache misses |
| `shinku_cache_expired_hit_total` | counter | Sampled expired cache entries encountered in XDP |
| `shinku_cache_gen_mismatch_total` | counter | Sampled generation mismatches (slot reuse detection) |
| `shinku_cache_seq_conflict_total` | counter | Sampled seqlock read conflicts |
| `shinku_xdp_tx_total` | counter | Sampled XDP_TX responses sent |
| `shinku_tc_capture_total` | counter | Sampled TC-captured DNS responses |
| `shinku_tc_ringbuf_drop_total` | counter | Sampled TC ring buffer reservation drops |
| `shinku_bpf_sample_mask` | gauge | Current sampling mask (events counted when `rand32 & mask == 0`) |

### Userspace Metrics

| Metric | Type | Description |
| :--- | :--- | :--- |
| `shinku_parser_reject_total` | counter | Total DNS parser rejections |
| `shinku_cache_insert_total` | counter | Successful cache inserts |
| `shinku_cache_insert_fail_total` | counter | Failed cache inserts |
| `shinku_cache_cleanup_removed_total` | counter | Expired entries removed by cleanup thread |
| `shinku_rb_pkt_poll_error_total` | counter | Packet ring buffer poll errors |

### Parser Reject Reasons

The `shinku_parser_reject_reason_total` counter provides detailed breakdown by rejection reason:

| Label (`reason=`) | Description |
| :--- | :--- |
| `not_response` | Packet is a query, not a response |
| `bad_qdcount` | Question count is not 1 |
| `tc` | Truncation flag is set |
| `rcode` | Response code is non-zero |
| `no_answer` | Answer count is 0 |
| `malformed_name` | DNS name parsing failed |
| `malformed_question` | Question section parsing failed |
| `malformed_rr` | Resource record parsing failed |
| `unsupported_rtype` | Record type not supported (not A/AAAA/CNAME) |
| `cname_no_terminal` | CNAME chain without terminal A/AAAA for A/AAAA query |
| `bad_ecs` | EDNS Client Subnet with non-zero scope |
| `bad_ttl` | TTL is 0 or invalid |

### CLI Options

```text
-o, --obs             Enable userspace observability (default: 1)
-p, --obs-bpf         Enable BPF observability sampling (default: 0)
-k, --obs-bpf-mask    BPF sampling mask (default: 0xff)
-m, --metrics-port    HTTP metrics port (default: 9095)
```

### Compile-Time Control

For zero-overhead in production, disable at compile time:

```bash
meson setup -Dobs=false -Dobs_bpf=false build
```

This removes all instrumentation code paths entirely.

## Testing

*   Unit tests: Run `meson test -C build`. This includes 48 tests covering the hash function, parser, and c-ares integration.
*   Integration tests: Run `sudo python3 tests/integration/test_dns_cache.py -v`. This suite contains 9 tests.
*   Benchmarks: Run `sudo bash tests/benchmark/run_benchmark.sh`.

## Development

### Static Analysis

The project uses clang-tidy for static analysis. Install it first:

```bash
sudo dnf install clang-tools-extra
```

Run analysis:

```bash
just tidy          # Check for issues
just tidy-fix      # Auto-fix where possible
```

### Code Formatting

Run clang-format on all source files:

```bash
just fmt
```

Configuration files:
*   `.clang-format` — Code formatting rules
*   `.clang-tidy` — Static analysis checks

## Project Structure

```text
.
├── docs/                 # Documentation and references
├── meson.build           # Build configuration
├── src/
│   ├── bpf/              # BPF source code (cache and helpers)
│   ├── cli/              # CLI and configuration handling
│   ├── core/             # Core logic and DNS processing
│   └── include/          # Shared headers and constants
└── tests/                # Unit, integration, and benchmark tests
```

## Design Documentation

For technical details on the implementation, see `docs/design.md`.

## References

*   Reference papers located in `docs/reference/`
*   [BPF Arena documentation](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARENA/)

## License

This project uses a dual-license model:

*   **BPF programs** (`src/bpf/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) (required by the Linux kernel for BPF programs that call GPL-only helpers).
*   **Userspace code** (`src/core/`, `src/cli/`, `src/include/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) OR [Apache-2.0](LICENSE-APACHE), at your option.

See [LICENSE-GPL2](LICENSE-GPL2) and [LICENSE-APACHE](LICENSE-APACHE) for the full text of each license.
