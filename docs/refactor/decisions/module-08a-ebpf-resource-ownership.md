# Module 8A eBPF Resource Ownership Decisions

## Segment 16: Module 8A eBPF Resource Ownership

Decisions:

1. Module 8 starts with a hard prerequisite slice, 8A: eBPF Resource Ownership.
2. 8A removes the transitional `EbpfLoaderOps` + `void* context` + central `bpf_ctx` ownership boundary before introducing backend-neutral DNS/cache policy.
3. `EbpfBackend` remains the sole eBPF lifecycle object; a separate `EbpfRuntime` would duplicate the `Backend` contract without an independent consumer or lifetime.
4. `EbpfBackend` owns one `std::unique_ptr<EbpfNativeSession>`. This ownership is indirect but exclusive; no other production object shares or borrows the Session.
5. `ProductionEbpfNativeSession` is a stateful C++ wrapper around the C/libbpf API. One private `NativeResources` aggregate owns the generated skeleton, manual XDP and TCX links, legacy TC state, packet and log rings, and the temporary cache/parser bridge.
6. Native pointers and C structs remain private to `ProductionEbpfNativeSession`; the Session interface does not expose raw pointers, generated skeleton types, opaque resource handles, type-erased handle state, or a resource registry.
7. `EbpfNativeSession` exposes native actions only: capability probes, interface lookup, fixed skeleton preparation, one attach attempt, ring creation and polling, expired-entry cleanup, retry waiting, and aggregate release.
8. `EbpfNativeSession` must not expose `start()`, `stop()`, `run()`, `setup_backend()`, Backend state, retry policy, fallback policy, or cleanup scheduling.
9. `prepare_skeleton()` may combine the fixed native sequence of installing the libbpf print callback, opening the generated skeleton, configuring the arena, disabling auto-attach for manually owned programs, loading, and attaching generated programs. It does not make Backend policy decisions.
10. `EbpfBackend` owns lifecycle orchestration, error context and mapping, XDP retry, TCX-to-legacy fallback, ring polling semantics, packet timeout policy, and cleanup-worker scheduling.
11. The Backend lifecycle remains `probe -> start -> repeated poll -> stop`; `start()` does not enter the long-running poll loop, and no separate `init()` phase is introduced.
12. `BackendRunner` remains the only lifecycle state authority and caller. Backend lifecycle hooks are protected and Runner-owned; tests drive concrete Backends through `BackendRunner`.
13. Start failure leaves cleanup owed. `BackendRunner` invokes `stop()` for partial startup resources, while Session destruction provides a final `noexcept` best-effort release path.
14. The cleanup loop belongs to a private Backend-owned `CleanupWorker` using `std::jthread` and stop-aware C++ wait primitives. It waits one full configured interval before the first cleanup pass and is joined before Session release.
15. `ProductionEbpfNativeSession::release()` owns native dependency order: close packet and log rings, detach manual links, detach legacy TC, destroy only a clsact created by this Session, release the bridge, then destroy the skeleton.
16. Session release attempts every independent native release, returns the first error, and preserves still-owned resources plus their dependencies for a later cleanup attempt when a native operation does not consume them.
17. XDP and TCX auto-attach are disabled before generated skeleton attachment. Manually attached XDP and TCX links are owned only by the Session's dedicated raw-pointer fields and are not written into generated skeleton link fields.
18. Legacy TC tracks whether this Session created clsact. A pre-existing clsact is never destroyed, including when filter attachment fails.
19. The intentional `void*` values are confined to libbpf and legacy C callback trampolines inside the production Session implementation. `bpf_ctx` is not retained as a Host Runtime ownership object.
20. Session methods return `std::expected<T, std::error_code>`. Errno-style failures use `std::generic_category()` only where the wrapped API has an errno-style contract; `EbpfBackend` adds stable Backend error semantics and operation context.
21. Production and tests implement the same private `EbpfNativeSession` interface. `make_backend(const Config&)` injects `ProductionEbpfNativeSession`, while focused tests inject `FakeEbpfNativeSession`.
22. `FakeEbpfNativeSession` uses independent result queues and an explicit call trace. It does not allocate fake native pointers or reproduce production resource-handle state.
23. The old `EbpfPlatform`, per-resource opaque Handle hierarchy, private type-erased Handle implementations, and `dynamic_cast`-based production extraction are removed.
24. 8A preserves the attach sequence: generated skeleton attachment, optional log ring, XDP retry, TCX retry with legacy TC fallback, packet ring creation, then cleanup-worker startup.
25. 8A preserves ring behavior: log-ring `EINTR` returns `NoWork` before packet polling, other log-ring failures are non-fatal warnings, packet-ring `EINTR` returns `NoWork`, and other packet-ring failures return `PollFailed`.
26. The TCX fallback loop remains Backend policy: each unsupported TCX result triggers one legacy TC attempt; after a failed legacy attempt the Backend waits and retries TCX for at most five rounds with the existing backoff.
27. The existing BPF log callback remains in `ProductionEbpfNativeSession`; the general diagnostics/logging boundary remains deferred to Module 10.
28. The optional `ebpf.packet_poll_timeout` is materialized as `100ms` when absent, validated from `1ms` through `1s`, and applies only to packet-ring polling. Log-ring polling keeps a private `100ms` timeout.
29. Module 8B/8C do not depend on `EbpfNativeSession`. Module 8D may request only the narrow native storage binding needed by the cache implementation; cache and DNS policy must not move into the Session.
30. `make_backend(const Config&)` remains the production assembly entry point. A `BackendFactory` type is deferred until multiple construction sources, registry discovery, or injected construction policy create a concrete need.

Constraint:

- This slice must preserve the eBPF Operational Loops: BPF attach/detach, packet ring polling, cleanup scheduling, signal-driven shutdown through `BackendRunner`, and cleanup after partial startup.
- The 8A test boundary should let unit tests cover lifecycle sequencing and error mapping without root, real interfaces, BPF attachment, or specific kernel feature availability.
- See [ADR-0011](../adr/0011-ebpf-runtime-resource-ownership.md).
- See [ADR-0012](../adr/0012-runner-exclusive-backend-lifecycle.md).
