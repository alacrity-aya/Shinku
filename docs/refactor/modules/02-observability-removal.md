# Module 2: Observability Removal

Goal:

- Remove the current Observability Surface completely without deleting backend-critical Operational Loops.

Scope:

- Remove degraded mode, runtime event bus, health/readiness HTTP endpoints, Prometheus metrics, BPF counters, dashboards/options, and observability tests.
- Preserve BPF attach/detach, ring polling, cleanup scheduling, and signal-driven shutdown.

Likely files:

- `meson.build`
- `meson.options`
- `tests/unit/meson.build`
- `src/core/obs_http.c`
- `src/core/obs_http.h`
- `src/core/obs_metrics.c`
- `src/include/obs_metrics.h`
- `src/include/obs_bpf_metrics.h`
- `src/core/degraded_mode.c`
- `src/include/degraded_mode.h`
- `src/runtime/events.c`
- `src/runtime/events.h`
- `tests/unit/obs/`
- `tests/unit/degraded/`
- `tests/unit/runtime/`
- observability references in `src/core/loader.c`, `src/core/dns_parser.c`, `src/core/cache_ops.c`, and `src/core/cache_types.h`

Verification:

- `meson compile -C build`
- `meson test -C build`

Result:

- Removed degraded mode, runtime event bus, health/readiness HTTP endpoints, Prometheus metrics, BPF counters, observability build options, Grafana/Prometheus files, and observability-specific unit tests.
- Preserved eBPF attach/detach, packet/log ring polling, cache cleanup scheduling, signal handling, and shutdown.
- Updated the soak script to launch through TOML config and rely on traffic/process checks instead of deleted metrics endpoints.
- `meson compile -C build` passes on 2026-07-19 after Module 2 removal.
- `ASAN_OPTIONS=detect_leaks=0 meson test -C build --no-rebuild` now reports 7/10 passing. Remaining failures are the known legacy baseline: `Arena List Test` and `Arena Hash Table Test` require root in this environment, and `Cache Store Correctness Test` remains a pre-existing arena/BPF-map baseline failure.

Rollback:

- Revert only Module 2 edits and keep Module 1 notes.
