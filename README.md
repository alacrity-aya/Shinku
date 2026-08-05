# Shinku

<p align="center">
  <img src="asserts/CG.avif" alt="Shinku" width="600">
</p>

An eBPF-based DNS caching proxy that serves cached responses at the XDP layer for near-line-rate performance. The project is mid-refactor from a C codebase into a C++23 Host Runtime with a backend-neutral cache domain, an eBPF backend, and a planned DPDK backend.

## Key Features

*   XDP fast path: Cache hits are served via `XDP_TX` directly, bypassing the kernel network stack.
*   TC response capture: Upstream responses are captured at the TC egress hook and emitted to userspace for correlation.
*   BPF Arena memory: Shared memory between XDP programs and userspace, requiring Linux 6.9 or newer.
*   Backend-neutral cache domain: Backend-agnostic C++ types for cache keys, DNS policy, store admission, and cache entries.
*   Pluggable backend interface: A synchronous `Backend` lifecycle (`probe` / `start` / `poll` / `stop`) with eBPF as the runnable backend and DPDK planned.
*   Pending query correlation: Bounded, short-lived records authorize only the matching response to enter the cache fill path.
*   Seqlock-published storage: XDP reads coherent snapshots of the shared cache storage published by userspace.
*   Fail-open behavior: Cache failures degrade to forwarding or bypass, never DNS outages.
*   TOML configuration: A single config file selects the backend and cache policy; CLI flags are limited to choosing the file.
*   Conditional BPF logging: A compile-time flag removes logging overhead from production builds.

## Architecture Overview

The system uses a three-layer design to process DNS traffic:

1.  XDP program (`cache.bpf.o`, `xdp` section): Handles ingress. It parses DNS queries, computes a cache key, performs cache lookups, and serves hits using `XDP_TX`.
2.  TC program (`cache.bpf.o`, `tc` section): Handles egress. It captures DNS responses destined for clients and forwards them to userspace via a packet ring buffer.
3.  Userspace Host Runtime (`shinku`): Receives captured response events, correlates them to Pending Queries, validates them with the backend-neutral DNS Policy, and publishes Cache Entries into the shared arena and cache maps.

```text
       +----------+         +----------+         +------------+
       |          |  query  |   XDP    |  query  |            |
       |  Client  +-------->+ (ingress)+-------->+ DNS Server |
       |          |         +----+-----+         |            |
       |          |              |               |            |
       |          |  reply  +----+-----+  reply  |            |
       |          |<--------+   TC    |<--------+            |
       +----------+         | (egress)|         +------------+
                            +----+-----+
                                 |
                    +------------v-----------+
                    |     Userspace          |
                    |   Host Runtime         |
                    |  (shinku)              |
                    |  - query correlation   |
                    |  - DNS policy          |
                    |  - store admission     |
                    +------------+-----------+
                                 |
                    +------------v-----------+
                    |  BPF Arena + maps      |
                    |  (seqlock-published)   |
                    +------------------------+
```

The BPF Arena and cache maps are shared resources accessed by both the eBPF programs and the userspace daemon. `xdp_pass.bpf.o` is a dummy pass-through program used on veth peers so that `XDP_TX` traffic is accepted.

## Requirements

*   Linux kernel 6.9 or newer (for BPF Arena support)
*   Clang/LLVM (for BPF target compilation)
*   Meson build system (C++23)
*   libbpf and bpftool (BPF loading and skeleton generation)
*   libcap, tomlplusplus, and argparse (fetched through Meson wrap when needed)
*   Root privileges for attaching XDP and TC programs

## Quick Start

Build the project using Meson:

```bash
meson setup build
meson compile -C build shinku
```

Or use the unified test runner, which configures the build and runs the unprivileged suite:

```bash
./scripts/run-tests.py quick
```

Run the system with a config file:

```bash
sudo ./build/shinku run --config shinku.toml
```

For development with BPF logging enabled:

```bash
meson setup -Dbpf_log=true build
```

For production without logging overhead:

```bash
meson setup -Dbpf_log=false build
```

## Configuration

Configuration is a TOML file selected by the CLI. The default path is `./shinku.toml`; override it with `shinku run --config path/to/file.toml`.

```toml
backend = "ebpf"

[ebpf]
iface = "eth0"
cleanup_interval = "10s"

[cache]
max_entries = 16384
max_response_bytes = 512
cache_negative = true
max_pending_queries = 8192
pending_query_timeout = "2s"
```

Schema notes:

*   `backend` selects the backend: `"ebpf"` (runnable today) or `"dpdk"` (planned).
*   `[ebpf]` holds eBPF backend settings; `iface` names the interface, `cleanup_interval` is a duration string (`ms`, `s`, or `m`).
*   `[cache]` is backend-neutral cache policy. `max_response_bytes` limits the size of a served response, and `cache_negative` enables NXDOMAIN/NODATA caching.

## Usage

```text
shinku run [--config path]
```

The CLI is intentionally minimal during the refactor:

*   `shinku run` — run with `./shinku.toml`.
*   `shinku run --config path` — run with the given TOML file.
*   `shinku --help`, `shinku run --help` — show usage.
*   `shinku --version` — show the version.

Note: When using `XDP_TX` on veth pairs, load `xdp_pass.bpf.o` on the peer interface to ensure traffic passes correctly.

## Performance

The frozen measurement contract for the current system is the PERF-M8-1 benchmark, defined in [`docs/refactor/decisions/module-08-performance-evidence.md`](docs/refactor/decisions/module-08-performance-evidence.md). It compares a CoreDNS service with and without Shinku across a hot single-name workload and a Zipfian hot set. The harness is implemented (`tests/benchmark/`, `scripts/run-perf-m8.sh`) and its privileged smoke has passed, but canonical evidence is still pending, so no product performance pass line is set.

Earlier measurements from the legacy Unbound harness are recorded in [`docs/performance.md`](docs/performance.md); they are not baselines for the new system. On a veth pair with generic XDP, that harness observed ~425K QPS with a 4.8x average-latency reduction for cache hits.

## Observability

The previous HTTP observability surface has been removed during the C++ refactor. The current MVP does not expose `/healthz`, `/readyz`, `/metrics`, Prometheus configuration, Grafana dashboards, degraded-mode state, or BPF-side observability counters.

Operational loops remain in place: eBPF attach/detach, packet and log ring polling, cleanup scheduling, signal handling, and shutdown. Runtime diagnostics/logging is a planned follow-up module.

## Testing

The unified runner builds the project and drives all local suites:

```bash
./scripts/run-tests.py quick      # build + unprivileged unit tests
./scripts/run-tests.py check      # quick + privileged + integration
./scripts/run-tests.py all        # check + fuzz + soak
./scripts/run-tests.py unit fuzz  # any combination of suites
```

Use `--help` for timing, sudo, and fail-fast options. `--sudo=never` forbids privilege elevation; eBPF tests require a capable kernel, libbpf, `bpftool`, and root.

Unit tests are registered in `tests/unit/meson.build` and cover the arena helpers, config loader, cache domain contract, DNS policy engine, eBPF cache store, pending query cleaner, correlated event consumer, cache/production verifier gates, CLI parser, process control, backend runner, and eBPF backend. Integration tests live in `tests/integration/`, fuzz smoke in `tests/fuzz/`, and soak in `tests/soak/`.

## Benchmarking

The PERF-M8-1 harness builds `shinku_bench` and the pinned CoreDNS source, generates deterministic workloads, and writes raw artifacts plus aggregate JSON/Markdown reports under `tests/benchmark/results/` (which is not committed):

```bash
sudo bash scripts/run-perf-m8.sh                                # short smoke gate (default)
sudo bash scripts/run-perf-m8.sh --full --canonical             # five-round canonical run
python3 scripts/render-perf-m8-report.py tests/benchmark/results/<run-id> -o report.html
```

`--canonical` requires a clean repository; `--full` runs the five-round measurement. The renderer accepts a `summary.json` path or a benchmark result directory and emits a self-contained HTML report.

Focused unprivileged tests for the harness helpers run under `./scripts/run-tests.py unit`.

## Soak Testing (Real Upstream via Docker Unbound)

Shinku includes a real-soak infrastructure path that uses:

- existing netns/veth topology (`tests/integration/topology.py`),
- a real upstream DNS server in Docker (`mvance/unbound`),
- Shinku attached on `veth-host`,
- periodic traffic/resource logs under `tests/soak/results/<run-id>/`.

Run with a custom duration/interval:

```bash
sudo env SOAK_DURATION_SEC=7200 SAMPLE_INTERVAL_SEC=20 tests/soak/run_soak_with_unbound_docker.sh
```

Notes:

- Requires root privileges, the Docker daemon, and a built `build/shinku` binary.
- Warm-refresh is treated as advanced optional behavior; the soak baseline does not assume it is enabled.

## Development

### Static Analysis

The project uses clang-tidy, exposed as Meson run targets:

```bash
meson compile -C build tidy      # Check for issues
meson compile -C build tidy-fix  # Auto-fix where possible
```

The wrapper lives in `scripts/run-clang-tidy.sh`.

### Code Formatting

Run clang-format on all C/C++ source files (not Python):

```bash
clang-format -i <files>
```

Configuration files:

*   `.clang-format` — Code formatting rules (four spaces, 120-column limit)
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

# Or initialize submodules in an existing clone
git submodule update --init --recursive

# Generate documentation
meson setup build
ninja -C build docs
```

**View documentation:**

```bash
xdg-open build/docs/html/index.html
```

Generated files are written to `build/docs/html/` and should not be committed to Git.

## Project Structure

```text
.
├── docs/                 # Design, architecture, ADRs, refactor plans and decisions
├── scripts/              # Test runner, benchmark, and tooling entry points
├── src/
│   ├── backend/          # Backend interface, BackendRunner, eBPF backend and cache store
│   ├── bpf/              # BPF programs and helpers (cache.bpf.c, cache_bpf_*.h, arena/)
│   ├── cache/            # Backend-neutral cache domain and DNS policy
│   ├── cli/              # CLI selector subcommand and main entry point
│   ├── config/           # TOML config loader and validation
│   ├── include/          # Shared C ABI headers (ebpf_cache_abi.h, bpf_log.h)
│   ├── process_control/  # Signal handling and shutdown request propagation
│   └── generated/        # Build-generated version header
└── tests/                # Unit, integration, fuzz, soak, and benchmark tests
```

## Design Documentation

*   [`CONTEXT.md`](CONTEXT.md) — project glossary and refactor language.
*   [`docs/refactor-plan.md`](docs/refactor-plan.md) — refactor roadmap and module status.
*   [`docs/refactor/decisions/`](docs/refactor/decisions/) — confirmed design decisions and frozen contracts.
*   [`docs/architecture.md`](docs/architecture.md) — module relationships and data flow.
*   [`docs/design.md`](docs/design.md) — packet-path design.

## References

*   Reference papers located in `docs/reference/`
*   [BPF Arena documentation](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARENA/)

## License

This project uses a dual-license model:

*   **BPF programs** (`src/bpf/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) (required by the Linux kernel for BPF programs that call GPL-only helpers).
*   **Userspace code** (Host Runtime and control-plane under `src/backend/`, `src/cache/`, `src/cli/`, `src/config/`, `src/process_control/`, `src/include/`): Licensed under [GPL-2.0-only](LICENSE-GPL2) OR [Apache-2.0](LICENSE-APACHE), at your option.

See [LICENSE-GPL2](LICENSE-GPL2) and [LICENSE-APACHE](LICENSE-APACHE) for the full text of each license.
