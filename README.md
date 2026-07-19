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

The previous HTTP observability surface has been removed during the C++/DPDK refactor. The current MVP does not expose `/healthz`, `/readyz`, `/metrics`, Prometheus configuration, Grafana dashboards, degraded-mode state, or BPF-side observability counters.

Operational loops remain in place: eBPF attach/detach, packet and log ring polling, cleanup scheduling, signal handling, and shutdown.

## Testing

*   Unit tests: Run `meson test -C build`. This includes 48 tests covering the hash function, parser, and c-ares integration.
*   Integration tests: Run `sudo python3 tests/integration/test_dns_cache.py -v`. This suite contains 9 tests.
*   Benchmarks: Run `sudo bash tests/benchmark/run_benchmark.sh`.

## Soak Testing (Real Upstream via Docker Unbound)

Shinku includes a real-soak infrastructure path that uses:

- existing netns/veth topology (`tests/integration/topology.py`),
- real upstream DNS server in Docker (`mvance/unbound`),
- Shinku attached on `veth-host`,
- periodic traffic/resource logs under `tests/soak/results/<run-id>/`.

Quick smoke run (5 minutes default):

```bash
just soak-up
just soak-run
```

24h run:

```bash
just soak-up
just soak-run-long
```

Or run directly with custom duration/interval:

```bash
sudo env SOAK_DURATION_SEC=7200 SAMPLE_INTERVAL_SEC=20 tests/soak/run_soak_with_unbound_docker.sh
```

Notes:
- Requires root privileges, Docker daemon, and built `build/shinku` binary.
- Warm-refresh is treated as advanced optional behavior; soak baseline does not assume it is enabled.

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

### API Documentation (Doxygen)

Shinku supports generating C API documentation via Meson+Doxygen with the [doxygen-awesome-css](https://github.com/jothepro/doxygen-awesome-css) theme for a modern, clean look.

**Prerequisites:**
- Doxygen 1.9+
- Graphviz (for call graphs and dependency diagrams)

**Setup:**

```bash
# Clone with submodules (includes doxygen-awesome-css theme)
git clone --recursive https://github.com/alacrity-aya/Shinku.git

# Or initialize submodules in existing clone
git submodule update --init --recursive

# Generate documentation
meson setup build
ninja -C build docs
```

**View documentation:**

```bash
# Open in browser
xdg-open build/docs/html/index.html
```

**Features:**
- Sidebar-only navigation layout
- Interactive SVG call graphs and dependency diagrams
- Syntax-highlighted code blocks
- Dark mode support (toggle in top-right corner)

Generated files are written to `build/docs/html/` and should not be committed to Git.

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

For module relationships and runtime data-flow, see `docs/architecture.md`.

## References

*   Reference papers located in `docs/reference/`
*   [BPF Arena documentation](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARENA/)

## License

This project uses a dual-license model:

*   **BPF programs** (`src/bpf/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) (required by the Linux kernel for BPF programs that call GPL-only helpers).
*   **Userspace code** (`src/core/`, `src/cli/`, `src/include/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) OR [Apache-2.0](LICENSE-APACHE), at your option.

See [LICENSE-GPL2](LICENSE-GPL2) and [LICENSE-APACHE](LICENSE-APACHE) for the full text of each license.
