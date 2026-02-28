# dns-cache

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
3.  Userspace (dns-cache): Receives responses from the ring buffer, validates and decompresses them, then stores the data into the BPF arena and cache_map.

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
                        |   (dns-cache)    |
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
meson compile -C build dns-cache xdp_pass.bpf.o
```

Run the system:

```bash
sudo ./build/dns-cache -i eth0
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
dns-cache [OPTIONS]
  -i, --interface IFACE    Network interface to attach (default: lo)
  -l, --log-level LEVEL    Log level: debug, info, warn, error (default: info)
  -a, --arena-pages PAGES  Arena size in pages (default: 2112)
```

Note: When using XDP_TX on veth pairs, load `xdp_pass.bpf.o` on the peer interface to ensure traffic passes correctly.

## Performance

The following results were recorded on a veth pair using generic XDP/SKB mode. Native XDP on physical network interfaces is expected to provide even greater performance gains.

| Metric | Baseline (Unbound) | With dns-cache | Improvement |
| :--- | :--- | :--- | :--- |
| QPS | 349,636 | 425,170 | 1.22x |
| Avg Latency | 24µs | 5µs | 4.8x |

Detailed methodology and full results are available in `docs/performance.md`.

## Testing

*   Unit tests: Run `meson test -C build`. This includes 48 tests covering the hash function, parser, and c-ares integration.
*   Integration tests: Run `sudo python3 tests/integration/test_dns_cache.py -v`. This suite contains 9 tests.
*   Benchmarks: Run `sudo bash tests/benchmark/run_benchmark.sh`.

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
*   [BPF Arena kernel documentation](https://docs.kernel.org/bpf/bpf_arena.html)

## License

GPL (matches the license of the BPF programs)
