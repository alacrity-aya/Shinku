# Module 8: Cache/DNS Module

Goal:

- Separate backend-neutral DNS/cache policy from eBPF-specific storage details.
- Remove the transitional eBPF loader ownership boundary before moving DNS/cache policy.

Scope:

- Preserve DNS parsing, ECS behavior, cache admission/eviction, negative caching, TTL behavior, and arena safety semantics.
- Do not design DPDK-specific behavior here beyond what the backend-neutral interface requires.

## Slices

### 8A: eBPF Resource Ownership

Purpose:

- Replace `EbpfLoaderOps`, `void* context`, and central `bpf_ctx` ownership with a stateful private C++ `EbpfNativeSession` owned exclusively by `EbpfBackend`.
- Keep `EbpfBackend` as the only Runner-facing lifecycle object. It owns `probe -> start -> repeated poll -> stop`, retry/fallback policy, polling policy, cleanup scheduling, and Backend error mapping.
- Let `ProductionEbpfNativeSession` own all native C/libbpf resources in one private raw-resource aggregate: generated skeleton, manual XDP/TCX links, legacy TC state, rings, and the temporary cache/parser bridge.
- Do not introduce public or type-erased per-resource Handle classes. Native pointers remain private to the production Session implementation.
- Keep the Session interface free of `start`, `stop`, `run`, `setup_backend`, Backend state, Stop Requests, and complete retry/fallback orchestration.
- Allow the Session to combine fixed native mechanics such as skeleton open, arena sizing, auto-attach disablement, load, and generated attachment into `prepare_skeleton()`.
- Keep XDP retry and TCX-to-legacy-TC fallback loops in `EbpfBackend`; each Session attach method performs one native attempt.
- Keep `std::jthread` cleanup scheduling in `EbpfBackend`. The worker waits one full interval before its first pass and uses a stop-token-aware wait for prompt shutdown.
- Return Session results as `std::expected<T, std::error_code>` and map them to contextual `BackendError` values in Backend.
- Keep the existing libbpf print callback in `ProductionEbpfNativeSession`; defer the general diagnostics boundary to Module 10.
- Preserve zero-allocation packet callback behavior. The C callback and `void*` context stay inside the intentional libbpf/legacy bridge boundary.
- Keep the current C DNS parser/cache path as a private transitional Session dependency. Do not redesign DNS/cache policy in 8A.

Ownership:

| Resource | Sole owner | Release mechanics |
| --- | --- | --- |
| Generated skeleton | `ProductionEbpfNativeSession` | Session release/destructor |
| Manual XDP and TCX links | `ProductionEbpfNativeSession` | Session release/destructor |
| Legacy TC filter and clsact ownership bit | `ProductionEbpfNativeSession` | Detach filter; destroy clsact only when created by this Session |
| Log and packet rings | `ProductionEbpfNativeSession` | Free before links and skeleton |
| Temporary cache/parser bridge | `ProductionEbpfNativeSession` | Release after callback users and before skeleton |
| Cleanup worker | `EbpfBackend` | Stop and join before Session release |

Behavior retained:

- Attach sequence: skeleton preparation, bridge, optional log ring, XDP retry, TCX retry with legacy TC fallback, packet ring, cleanup worker.
- Five attach attempts with the existing exponential backoff, including the final failed-attempt wait.
- Each unsupported TCX attempt may invoke one legacy TC attempt before the next TCX retry.
- Log-ring `EINTR` returns `NoWork`; other log errors are non-fatal warnings.
- Packet-ring `EINTR` returns `NoWork`; other packet errors return `PollFailed`.
- Enabled log-ring creation and cleanup-thread creation failures are fatal startup failures.
- Start failures leave Runner-driven `stop()` responsible for releasing partially acquired Session state.
- Manual links are not written into generated skeleton link fields.
- Pre-existing clsact hooks are never destroyed by failed attach or shutdown.

Testing:

- `FakeEbpfNativeSession` implements the same private Session interface with independent result queues and call traces.
- Backend lifecycle tests remain Runner-driven and require no root, real interface, BPF attachment, or specific kernel feature support.
- Focused tests cover probe mapping, partial-start release, log-ring startup failure, attach retry/backoff, TC fallback, polling semantics, packet timeout, and Session release failure mapping.
- Native pointer ownership and actual attach/detach behavior remain integration-test responsibilities.

Implementation result:

- 8A is implemented in `EbpfBackend`, `EbpfNativeSession`, `ProductionEbpfNativeSession`, and the private `loader_cache_bridge` C adapter.
- The old loader, Platform, opaque Handle, type-erased State, and central `bpf_ctx` lifecycle paths are removed.
- `BackendRunner` remains the only caller of protected Backend lifecycle hooks.
- Optional `[ebpf].packet_poll_timeout` defaults to `100ms`, validates from `1ms` through `1s`, and affects only packet-ring polling.

### 8B: Backend-neutral Cache Domain

Purpose:

- Define backend-neutral cache policy types, typed store outcomes, capacity/response-size validation behavior, and controllable time where needed.
- Keep storage-specific arena/map/seqlock details out of the policy contract.

### 8C: DNS Policy Engine

Purpose:

- Move DNS response parsing, validation, ECS partitioning, negative caching, TTL selection, CNAME behavior, and TC/malformed bypass decisions into a backend-neutral C++ policy engine.

### 8D: eBPF Cache Store

Purpose:

- Adapt the eBPF map/arena storage implementation behind the backend-neutral cache store contract.
- Preserve seqlock, generation, slot-owner, admission metadata, eviction, and cleanup safety semantics.
- Obtain only the narrow native storage binding required from `EbpfNativeSession`; do not move cache policy into the Session.

### 8E: Composition and Cutover

Purpose:

- Wire packet-ring callbacks through the backend-neutral DNS/cache policy and the eBPF cache store.
- Activate `CacheConfig` behavior for the eBPF backend.
- Remove the legacy C parser/cache path when the new path has equivalent focused coverage.

Verification:

- DNS parser tests.
- Cache store tests.
- DNS hash tests.
- eBPF Backend remains runnable throughout the cutover.
