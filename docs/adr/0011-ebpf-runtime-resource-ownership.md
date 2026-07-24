# Stateful eBPF Native Session Owns C Resources

Module 8A replaces the transitional `EbpfLoaderOps` + `void* context` + central `bpf_ctx` boundary with a private C++ `EbpfNativeSession`. This decision supersedes the first 8A implementation based on a stateless `EbpfPlatform`, eight public opaque handle types, private type-erased handle state, and per-resource `dynamic_cast`. That design preserved strong type separation but made the C/libbpf adapter substantially larger than the lifecycle behavior it wrapped.

`EbpfBackend` remains the only Runner-facing lifecycle object. It implements `probe()`, `start()`, `poll()`, and `stop()`, and retains attach retry policy, TCX-to-legacy-TC fallback policy, polling semantics, cleanup scheduling policy, Backend error mapping, and runner-visible state. No separate `EbpfRuntime` is introduced.

`EbpfBackend` owns one `std::unique_ptr<EbpfNativeSession>`. Ownership is indirect but exclusive: the Session owns the generated skeleton, manually attached XDP and TCX links, legacy TC attachment and clsact ownership bit, packet and log rings, and the temporary legacy cache/parser bridge. `ProductionEbpfNativeSession` stores those native C resources as raw pointers and C structs inside one private `NativeResources` aggregate. Native pointers do not cross the Session interface.

The Session is a stateful C API wrapper, not a second Backend lifecycle. Its interface must not expose `start()`, `stop()`, `run()`, `setup_backend()`, Backend state, Stop Requests, or complete retry/fallback orchestration. Allowed operations are native actions such as capability probes, interface lookup, skeleton preparation, one XDP/TCX/legacy-TC attach attempt, ring creation and polling, cache cleanup, retry waiting, and native resource release.

Skeleton preparation may combine the fixed libbpf sequence of open, arena sizing, disabling generated auto-attach for manually attached programs, load, and generated attachment. This sequence has no Backend policy branch and is kept together to reduce C-boundary surface area. The Backend still sequences bridge creation, optional log-ring creation, manual attachment policy, packet-ring creation, and cleanup-worker startup.

`ProductionEbpfNativeSession::release()` owns native dependency order: packet and log rings are closed before links, the legacy filter is detached before an owned clsact is destroyed, and the bridge is released before the skeleton. Independent releases continue after an error; if legacy detach or owned-clsact destruction fails, that state and its skeleton dependency remain available for a later release attempt. A pre-existing clsact is never destroyed. Session destruction provides final `noexcept` best-effort release after Runner-driven cleanup.

The cleanup worker remains owned by `EbpfBackend` because cleanup interval, wait-before-first-run behavior, stop-aware joining, and fatal thread-start semantics are Backend operational policy rather than libbpf resource mechanics. The worker references the Session only while Backend ownership guarantees that the Session outlives the worker.

Session operations return `std::expected<T, std::error_code>`. Errno-style libbpf results are converted at the Session boundary only when the wrapped API defines that convention. `EbpfBackend` adds operation context and maps failures into `BackendError`. Runtime log-ring errors remain non-fatal, while packet-ring errors remain fatal except for interruption.

Production and tests implement the same private Session interface. `make_backend(const Config&)` injects `ProductionEbpfNativeSession`; Runner-driven Backend tests inject `FakeEbpfNativeSession`. The fake uses independent result queues and call traces but does not create fake native pointers or duplicate resource-handle state.

The legacy C cache/parser bridge remains a private Session dependency until Module 8D/8E replaces it. Future cache work may request a narrow eBPF storage binding from the Session, but DNS policy, TTL, ECS, admission, and cache policy must not move into the Session.

Implementation note: 8A removes `EbpfLoaderOps`, `EbpfLoaderConfig`, `loader.c`, `loader.h`, `ebpf_platform.h`, `ebpf_platform.cc`, the opaque handle hierarchy, and the central `bpf_ctx` lifecycle path. The remaining C adapter is limited to legacy cache/parser state and callback functions.
