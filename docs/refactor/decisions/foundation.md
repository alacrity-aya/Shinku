# Foundation Decisions

## Segment 1: Refactor Scope

Decisions:

1. All Host Runtime `.c` files should gradually become `.cc`.
2. The current Observability Surface is deleted in full, including degraded mode, runtime event bus, health/readiness endpoints, Prometheus metrics, BPF counters, dashboard files, and observability tests.
3. The current eBPF Backend must remain runnable during the refactor.

Constraint:

- Deleting observability must not delete backend-critical Operational Loops. Ring-buffer packet polling, cleanup scheduling, signal handling, and eBPF attach/detach remain product behavior, not observability.

## Segment 2: C++ Standard and Migration Order

Decisions:

1. Meson targets `cpp_std=c++23`, not compiler-tracking `c++2c`.
2. A new C++ domain model is introduced before DPDK backend implementation.
3. The first practical C++ slice is the Config domain model and TOML Config File loader. `src/cli` is deferred as a thin config-selector subcommand.

Constraint:

- The first C++ conversion must keep the current eBPF backend runnable. The TOML loader may call existing C loader/config code through a temporary C Boundary until the lifecycle/domain model is ready.

## Segment 3: C++ Domain Model Boundary

Decisions:

1. The first domain model slice covers `Config` and `Backend Lifecycle` only.
2. Host Runtime operations return `std::expected<T, Error>` or typed status objects, not exceptions and not raw errno.
3. The domain model uses new C++ types immediately. The current eBPF Backend is connected through adapters rather than becoming the shape of the new model.

Constraint:

- `CacheKey`, `CacheValue`, and DNS parser result types are intentionally deferred. Pulling them into the first slice would couple the C++ migration to DNS semantic changes and make it harder to keep eBPF runnable.

## Segment 4: Backend Lifecycle State Machine

Decisions:

1. The public lifecycle state machine is simple: `Created -> Running -> Stopped -> Failed`.
2. `probe()` is a pre-start capability check with no persistent side effects. It answers whether the selected Backend is supported on the current host with the validated Config.
3. Backend selection is fixed at startup for the whole process lifetime. Runtime backend switching is out of scope.

Constraint:

- `probe()` can inspect system capabilities and configuration validity, and it may perform bounded transient capability probes that immediately release resources. It must not reserve hugepages, bind NIC ports, create production BPF maps, open BPF skeletons, spawn threads, attach programs, start packet processing, retain resources, or mutate process/global state.
- The Host Runtime calls `probe()` after Config Loader succeeds and before `start()`.
- If `probe()` reports an unsupported selected Backend, startup fails. The system does not switch to another Backend and the eBPF Backend does not fall back to a compatible store when BPF arena is unavailable.
