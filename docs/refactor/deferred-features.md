# Deferred Feature Backlog

Purpose:

- Record product capabilities intentionally excluded from the current MVP or active module.
- Preserve the reason, prerequisite, and reopening trigger so a temporary limitation does not become an accidental permanent contract.
- Keep deferred product work separate from implementation alternatives that require benchmark evidence.

This file is not a promise that every conditional extension will be implemented. `Deferred` items are intended follow-up work after the MVP; `Conditional` items are reconsidered only when a concrete deployment, consumer, or requirement appears. Performance-only alternatives belong in the [Refactor Benchmark Backlog](benchmark-backlog.md).

## Deferred After MVP

| ID | Feature | Current MVP boundary | Reopening prerequisite | Source |
|---|---|---|---|---|
| DF-1 | Declared eBPF verifier support matrix | Module 8D only requires the selected fingerprint, worst-case TTL patch loop, and combined production path to load on the current development host. It ships one production BPF object and no runtime fallback. | Define supported kernels and compiler versions, run the verifier prototypes across that matrix, and select one production implementation at development time. Do not add runtime multi-object probing merely to claim compatibility. | Module 8D decision 8D-12 |
| DF-2 | ECS-aware Caching | ECS/EDNS Queries are Pass-through because `ARCOUNT != 0`; no ECS identity, prefix coverage, variant storage, or response synthesis enters Cache Domain identity. | A concrete deployment and traffic benchmark must show that ECS-bearing traffic materially limits the target QPS, p99, or DNS-service CPU goal. The design must account for ECS scope/source-prefix semantics and Backend constraints. | Module 8B/8C; ADR 0016 |
| DF-3 | Bounded asynchronous Cache Fill | Packet-ring callbacks synchronously call `DnsPolicy` and `CacheStore`; candidates borrow response and TTL-offset memory only for that call. | `PERF-8E-2` must show synchronous fill materially delays ring consumption. A future design owns bounded `FillWork` buffers and offsets, uses a preallocated pool and queue, and drops fill work rather than blocking when saturated. | Module 8B/8C/8E; ADR 0016 |

## Conditional Extensions

| ID | Feature | Current boundary | Reopening trigger | Source |
|---|---|---|---|---|
| DF-4 | Broader Cacheable Query Profile | The MVP caches tuple-symmetric IPv4/UDP standard recursive `A/IN` exchanges without an Additional Section. Other query types, EDNS forms, TCP, fragments, and changed endpoint identity bypass cache admission. | Add only from a concrete workload. Every semantic that can alter the answer must become Cache Key identity or be safely normalized, and each Backend must consume shared eligibility and hit vectors. | Module 8B/8E |
| DF-5 | NAT/proxy-aware Query Correlation | Correlation requires reversed endpoint identity at one Cache Point; NAT or proxy changes suppress Cache Fill while forwarding remains Fail-open. | A supported deployment topology cannot provide tuple symmetry. Any extension needs an explicit conntrack or proxy identity source rather than weaker packet-only matching. | Module 8B/8E; ADR 0016 |
| DF-6 | Richer Config sources and defaults | TOML selected by the thin CLI remains canonical; most fields are explicit, and env/search-path configuration is inert. | A concrete operator workflow requires field defaults, environment overrides, XDG or `/etc` discovery, or a broader CLI. Config Loader must remain the schema authority. | Modules 3 and 4; ADR 0007 |
| DF-7 | Production Manual and Timeout Stop Conditions | The lifecycle contract defines `Manual` and `Timeout`, but production composition currently supplies only process-signal shutdown. | An in-process control API or bounded-runtime execution mode becomes a real requirement. Stop sources may request shutdown but must not execute Backend stop. | Modules 5 through 7; ADR 0009 |
| DF-8 | Reintroduced Observability Surface | The previous health, readiness, metrics, event-bus, and dashboard surface remains deleted. Module 10 covers diagnostics/logging, not observability. | Scope a new operator contract explicitly after Backend boundaries stabilize; do not restore the deleted surface by incremental logging changes. | Module 2; ADR 0002 |
| DF-9 | Backend-specific cache tuning | `[cache]` contains backend-neutral semantics and hard requirements; concrete Stores privately choose their representation and policy. | A measured Backend-specific requirement cannot be expressed without semantic drift. Add overrides only through a dedicated ADR. | Module 8B; ADR 0008 |
| DF-10 | General-purpose DNS module | Cache-owned DNS parser and Policy internals remain under `src/cache/dns/`. | A second non-cache consumer creates a real reusable DNS parsing boundary. | Module 8C |
| DF-11 | Production BackendFactory or registry | `make_backend(const Config&)` remains the single production assembly function. | Multiple construction sources, plugin/registry discovery, or injected construction policy make a factory object materially useful. | Modules 6 through 8A; ADR 0010 |
| DF-12 | VLAN-aware Cache Namespace | The MVP Cacheable Packet Profile is untagged Ethernet on one isolated L2 domain. Inline `802.1Q`/`802.1ad` traffic and shared trunks, including hardware-stripped VLAN metadata, do not participate in Cache Hit, Pending, or Fill paths. | A concrete trunk or overlapping-address deployment requires caching across VLANs. Redesign Cache Namespace semantics, eBPF and DPDK physical keys, Pending identity, correlated-event metadata, XDP response handling, offload capability requirements, and shared isolation tests together; parser-only tag skipping is insufficient. | Module 8E decision 12; ADR 0015 |

## Scheduled Refactor Work

These are already represented as modules in the canonical plan and are listed here only to distinguish them from post-MVP feature ideas:

- Module 9 implements the DPDK Backend, including its concrete Cache Hit Path.
- Module 10 introduces runtime diagnostics/logging and migrates temporary C/libbpf output.
- Module 11 rewrites the remaining unreliable legacy test suite after runtime boundaries stabilize.

## Exclusions

The following are not deferred product features:

- round-robin versus CLOCK/TinyLFU, one mutex versus finer locking, owner sweep versus expiration heap, and seqlock scratch versus immutable QSBR are benchmark-driven implementation alternatives in `benchmark-backlog.md`;
- runtime Backend switching is explicitly out of scope, not planned follow-up work;
- BPF map pinning, external cache replication, distributed consistency, and active Kubernetes invalidation are not promised by the current refactor plan;
- historical deferrals already completed by later slices, such as replacing `EbpfLoaderOps`, typed native cleanup, and the C++ Cache/DNS domain types, are not backlog items.
