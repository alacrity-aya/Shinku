# Confirmed Refactor Decisions

## Starting Point

The refactor starts from `master` on branch `refactor`, not from an empty tree. The existing C code contains behavior that should be treated as regression evidence: DNS parsing, cache admission/eviction, ECS handling, negative caching, BPF arena safety, and tests. Preserve validated product semantics and Operational Loops, not implementation defects discovered while specifying the replacement.

## Known Goals

- Move all Host Runtime `.c` files to `.cc` over the refactor.
- Use C++23 for the Host Runtime: Meson should set `cpp_std=c++23`.
- Keep C where required by eBPF, kernel-facing code, generated BPF skeletons, or deliberately small C ABI boundaries.
- Add a DPDK Backend behind a C++ Cache Engine abstraction.
- Keep the current eBPF Backend runnable throughout the refactor.
- If the selected eBPF Backend is unsupported on the target kernel, such as missing usable BPF arena support, startup fails with an unsupported-backend error. There is no compatible-store fallback.
- Delete the current Observability Surface completely: degraded mode, runtime event bus, `/healthz`, `/readyz`, Prometheus metrics, BPF counters, Grafana/Prometheus files, and observability tests.
- Represent runtime parameters with a TOML Config File selected by a thin subcommand. Full CLI parsing is deferred and kept only as a future extension point.
- Add a runtime diagnostics/logging boundary after backend boundaries stabilize; do not let ad hoc `printf()`/`fprintf()` calls become the long-term architecture.

## Current Code Facts

- `src/core/loader.c` currently owns eBPF lifecycle, ring polling, and cleanup thread lifecycle.
- `src/core/dns_parser.c` performs response validation and cache insertion without the deleted observability counters.
- `src/core/cache_types.h` no longer carries observability state inside cache context.
- `src/bpf/cache.bpf.c` no longer contains BPF-side observability counters or sampling configuration.
- `meson.build` and `meson.options` no longer expose observability build flags.
- Tests include behavior tests that should be preserved; observability-specific tests have been deleted.
- The legacy XDP ECS query parser uses a fixed maximum-address bound before deriving the actual ECS address length, so common IPv4 `/24` queries cannot reach their ECS cache key.
- The legacy userspace ECS response parser rejects `SCOPE PREFIX-LENGTH > SOURCE PREFIX-LENGTH`, although RFC 7871 defines that as valid input requiring special cache treatment.
- The legacy cache key is a 32-bit FNV name hash plus question type and class, and under the MVP Query Profile the type and class are constant, so the effective key is 32 bits. By the birthday bound that is roughly a 3 percent chance of at least one colliding pair at the current 16384-entry map size and roughly 50 percent at the 65536 entries used in the example configuration. A collision does not cause a miss; it makes XDP serve one name's answer for a different name, repeatably for the whole entry lifetime, and downstream caches then propagate it. This is a defect rather than a representation detail.
- `CACHE_VALUE_FLAG_TC_FALLBACK` is written in `src/core/dns_parser.c` and read nowhere; the XDP hit path never inspects `cache_value.flags`. The truncated response is stored under the same Cache Key as the ordinary answer, so a truncated upstream response evicts the good cached answer for that name and every query is served a truncated response for the next five seconds. This is a legacy defect, not behavior to preserve.

## Candidate Work Slices

1. Establish build and test baseline on `refactor`.
2. Remove the current Observability Surface while preserving eBPF operational loops.
3. Introduce C++ build support without changing eBPF behavior.
4. Introduce the C++ Config domain model and TOML Config File loader before DPDK backend implementation.
5. Keep `src/cli` as a thin config-selector subcommand rather than the full configuration authority.
6. Convert Host Runtime modules from `.c` to `.cc` incrementally.
7. Define the C++ Cache Engine interface and backend-neutral DNS/cache types.
8. Split common DNS/cache policy from eBPF-specific loader/storage.
9. Implement DPDK Backend while keeping the eBPF Backend runnable.
10. Introduce a runtime diagnostics/logging boundary after backend runtime paths stabilize.
11. Reintroduce a cleaner Observability Surface later only if explicitly scoped.

## Decision Cadence

The refactor is designed and implemented module by module. Grill questions should stay scoped to the current module and avoid forcing decisions for later modules before their code boundary is being designed.

