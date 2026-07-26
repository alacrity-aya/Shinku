# Module 8: Cache/DNS Module

Goal:

- Separate backend-neutral DNS/cache policy from eBPF-specific storage details.
- Remove the transitional eBPF loader ownership boundary before moving DNS/cache policy.

Scope:

- Preserve validated DNS, admission/eviction, negative-cache, TTL, and arena-safety semantics. ECS-bearing exchanges use ECS Pass-through in the MVP; existing ECS code and tests are not a requirement to retain ECS-aware Caching during this module.
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

- Define the backend-neutral Cache Domain Contract: cache identity, candidate shape, store outcomes, error channel, cleanup behavior, and explicit time.
- Keep storage-specific arena, map, and seqlock details out of the contract.
- Limit the slice to the contract and its tests. Do not cut over the legacy parser/cache path and do not implement a concrete Cache Store.

Deliverable:

- `src/cache/` in namespace `shinku::cache`, with the file layout `cache_time.h`, `canonical_name.h`, `cache_key.h`, `cache_candidate.h`, `cache_store.h`, and `cache_store_error.h`, plus the `[cache]` Config Schema additions.
- Do not define a `CacheEntry` type. The stored form stays private to each concrete Store.
- Do not define a backend-neutral `PendingQuery` type or correlation interface. The eBPF Backend correlates entirely in BPF, so no Host Runtime object consumes such a type; model userspace correlation when the DPDK Backend needs one. The `[cache]` correlation fields still land here because Config Schema is a cross-module contract.
- Do not define the DNS Policy input type for a correlated Response; that boundary type belongs to 8C.
- Do not introduce a worker, queue, or memory pool. The contract stays compatible with a future asynchronous Cache Fill Path without providing one.
- Do not depend on `EbpfNativeSession`, libbpf, BPF map or arena types, DPDK types, or packet-buffer ownership types.

Cacheable Query Profile:

- Accept IPv4/UDP standard `QUERY` opcode messages with exactly one `A/IN` question, `RD=1`, `CD=0`, and `ARCOUNT=0`. A cacheable positive Response may contain a CNAME chain ending in A, and `NXDOMAIN` or `NODATA` for the same profile remains subject to Negative Cache Admission.
- Bypass every Query with an Additional Section, including EDNS, DNSSEC signaling, and ECS, plus `AAAA`, `SRV`, `TXT`, `MX`, `PTR`, multi-question messages, and TCP.
- Bypass a Response with `ARCOUNT != 0`, mirroring the Query rule. This also keeps the patch plan safe, because an OPT pseudo-record's TTL field carries an extended RCODE and flags rather than a TTL.
- Bypass a truncated Response. The legacy TC-fallback entry is not carried forward.
- Bypass a Response whose Cache Entry Lifetime would be zero. A zero TTL means "do not cache", and admitting it would consume Cache Capacity with an entry that can never be hit.
- Bypass a Response whose Cache Hit representation could exceed `max_response_bytes`, including fields generated or rebound for the current Query. Never truncate a Response for storage or emission, and never construct a Candidate for Store to reject.
- Later modules may broaden the profile, but every newly supported semantic that can change an answer must enter Cache Key identity or be normalized safely before it becomes cacheable.

Cache Key identity:

- Compose `CacheKey` from `CacheNamespace`, the canonical question name, question type, question class, and every other admitted semantic that can change the answer.
- Derive `CacheNamespace` from the original Query destination IPv4 address and UDP port, and keep it a field of the key rather than a Store parameter or a per-instance property. A Store may still shard its internal representation by namespace.
- Represent the canonical question name as a fixed-capacity, allocation-free DNS wire name: lowercase labels, no compression pointers, a terminating root label, and the DNS 255-byte limit.
- Treat the 32-bit FNV hash as neither the domain identity nor an acceptable Backend representation. Concrete Stores derive their own physical keys.
- Permit a physical key of plaintext `CacheNamespace` plus a 128-bit keyed fingerprint over the canonical name, type, and class. The fingerprint must be a keyed PRF with a per-process random secret; unkeyed 128-bit hashes are rejected because they restore an offline collision-construction primitive.

Cache Candidate:

- Make a Cache Candidate valid by construction at the DNS Policy boundary. Unsupported, malformed, or ineligible Responses produce a Bypass rather than a partially valid Candidate. Cache Store does not repeat DNS parsing or policy validation, but still enforces its own storage-format and capacity constraints.
- Shape `CacheCandidate` as `key` by value, `kind`, `lifetime`, a borrowed response span, and a borrowed TTL-offset span. Cache Store consumes both spans synchronously and retains neither.
- Do not add a separate upstream Transaction ID field. The verbatim template already carries it at offset 0, and a second copy would only create a disagreement to resolve.
- Represent Cache Entry Kind as a mutually exclusive `Positive`, `NxDomain`, or `NoData` value rather than Backend flags or Store-side DNS inference.
- Let the Candidate carry its TTL rather than a precomputed expiration timestamp.

Response Template:

- Store the upstream DNS message verbatim, from the DNS header to the end of the message and without Ethernet, IP, or UDP headers. Do not strip sections, decompress names, or rebuild the message; Cache Store treats the bytes as opaque.
- Keep the complete message including its Question Section. Fixed-size arena slots mean a compact header-plus-tail form buys no density while breaking the property that a stored template is a valid DNS message.
- Rely on Cache Key identity fixing the question wire length, so stored offsets and compression pointers stay valid and a pointer into the Question Section resolves against the current Query's own QNAME case.
- Record the byte offset of every TTL field in the message — Answer, Authority, and Additional — as the patch plan. A negative Response carries its only TTL in the Authority Section SOA, so an Answer-only plan would replay a fixed TTL and re-arm every downstream cache for a full TTL on each Cache Hit.
- Keep the patch plan a borrowed span with no capacity constant in the contract. Each Store derives its own worst case from `max_response_bytes` and returns `Rejected` when it cannot persist the complete plan; it must never truncate the plan and serve partially aged TTLs.

Cache Entry Lifetime:

- Define Cache Entry Lifetime as the minimum original TTL across every RR in the verbatim message, so the Authority and Additional Sections participate. The whole entry expires at that point, while Hit processing still ages every retained RR individually.
- Derive negative Cache Entry Lifetime from `min(SOA.TTL, SOA MINIMUM)` per RFC 2308 section 5, and Bypass a negative Response with no SOA in its Authority Section.
- Drop the legacy five-second negative floor, which kept serving answers past their authorization, and the legacy 600-second ceiling, which is an undocumented judgment that conflicts with TTL-only Freshness. A ceiling, if ever needed, becomes an explicit `[cache]` field with its own ADR.
- Keep this correctness lifetime distinct from the legacy minimum-TTL admission threshold, which is not part of the contract.

Cache Hit Semantics:

- Rewrite exactly three things on a Cache Hit: the Transaction ID, the Question Section bytes, and every RR TTL. Replay every header bit verbatim, including `AA`.
- Reduce each RR's original TTL by the time already spent in cache and round down to whole seconds, so a hit never overstates remaining lifetime even after sub-second residence.
- Do not rebind `RD`: the Cacheable Query Profile requires `RD=1`, so a stored Response can only be hit by a Query whose `RD` already matches.
- Rely on the invariant that a Cache Hit emits exactly as many bytes as the stored template, so one `max_response_bytes` bounds both storage and emission.
- Specify these as backend-neutral rules verified by shared Cache Hit vectors rather than as a shared function, because one hit path is BPF C and the other will be C++.

Cache Store contract:

- Express Cache Store as a runtime-polymorphic C++ interface whose virtual calls occur only on the Cache Fill and cleanup paths. Concrete Store types do not propagate through DNS Policy or composition templates.
- Give Cache Store no `lookup()` operation, so no virtual dispatch reaches a per-packet Cache Hit Path. A future DPDK userspace hit path calls its own concrete Store directly.
- Give Cache Store no capacity query. Because `probe()` must reject unsatisfiable limits before a Store exists, each Backend knows its own static ceiling independently.
- Give Cache Store no independent `start()`, `stop()`, or lazy-initialization state machine. A Backend creates it from validated limits and acquired native bindings during `start()`, treats creation failure as `StartFailed`, and releases it through RAII before releasing those bindings.
- Declare all operations `noexcept` and return every expected operational failure through `std::expected`. Callers add no exception-recovery guards.
- Support exactly one concurrent `store()` caller plus one `cleanup()` that may run concurrently with it. Concrete Stores own the synchronization their representation needs; Backend does not serialize the paths with a shared mutex, and this boundary never enters the XDP Cache Hit Path.
- Let each Store own storage-pressure admission and eviction strategy. The contract does not require every Backend to use the same algorithm, and the legacy minimum-TTL, dampening, frequency-sketch, and hot/cold algorithms are not part of it.

Store Outcomes:

- Standardize outcomes as `Inserted`, `Updated`, `Replaced`, and `Rejected`. Rejection is an ordinary policy result; only operational storage failures use the typed error channel.
- Return `Inserted` when a new key uses empty storage or reclaims an expired entry, because no live Cache Entry was displaced, and reserve `Replaced` for displacing a different entry that was still hit-visible at Store Admission time. Cleanup scheduling therefore never changes the logical outcome.
- Return `Updated` when an accepted Candidate matches an existing Cache Key: update that logical entry in place without evicting an unrelated entry or advancing replacement selection.
- Keep `Rejected` reason-free in the MVP, and require it to leave every existing Cache Entry hit-visible with unchanged payload, key ownership, and expiration state. A Store may still update private admission metadata such as a frequency estimate or victim-selection cursor.
- Define one Cache Publication point per concrete Store. `WriteFailed` guarantees the Candidate never became hit-visible, although a victim invalidated before publication may already have become a miss. Once publication succeeds, later bookkeeping cannot reclassify that write as failed.

Errors and cleanup:

- Return a small stable error code set for unavailable storage, write failure, and cleanup failure, with an optional underlying `std::error_code` cause. Do not expose map, arena, lock, or other Backend mechanics as public error codes, and do not carry a message string; the Cache Fill Path is `noexcept` and its errors may repeat indefinitely.
- Make expired-entry cleanup a bounded operation that receives current time and returns both `removed_entries` and `more_work`. The batch bound belongs to the Store, because its unit is representation-specific.
- When cleanup reports `more_work`, let the cleanup worker check its stop token and immediately run another bounded batch with a fresh timestamp; the configured interval resumes after completion or error.
- Treat an individual Cache Fill write failure as non-fatal: discard that fill attempt, report the typed error through the available diagnostic path, and keep polling instead of returning `PollFailed`.
- Treat an individual cleanup failure as non-fatal and retry on a later schedule. Hit-path expiration checks preserve response correctness while reclamation is delayed.
- Keep runtime Store errors Fail-open even when they repeat indefinitely, with no threshold that promotes them to `PollFailed`. The cache may converge to all misses while upstream forwarding continues.

Time:

- Pass current time explicitly to `store()` and `cleanup()` so tests control it without a Clock abstraction.
- Represent it as `CacheTime`, a `std::chrono::time_point` over a `CacheClock` tag that deliberately provides no `now()`. The clock domain differs per Backend, so any shared `now()` would be a convenient, compiling, silently wrong default for one of them. Each Backend constructs `CacheTime` from its own clock source at one visible place, and mixing in a `steady_clock::time_point` stays a compile error.

Config Schema:

- Keep `[cache]` the home of backend-neutral requirements and DNS Policy, and keep backend-specific cache tuning out of the Config Schema until a concrete requirement justifies it.
- Add required `max_pending_queries` and `pending_query_timeout` with no implicit defaults. The former is Pending Query Capacity, independent of `max_entries`; the latter uses the existing duration-string syntax and measures inactivity since the most recently observed Query with the same correlation identity. An identical retransmission refreshes `last_seen`, and the MVP adds no separate absolute Pending Query lifetime.
- Validate `max_entries >= 1`, `max_pending_queries >= 1`, `max_response_bytes` within `[128, 512]`, and `pending_query_timeout` within `[100ms, 10s]` in Config Loader.
- Justify the 512-byte ceiling as a DNS protocol rule rather than a Backend capability: an `ARCOUNT = 0` Query advertises no EDNS UDP payload size, so a larger cached Response could never be emitted legally and could never have arrived from upstream either. A smaller value is a legitimate storage-density setting because oversized Responses Bypass instead of being truncated.
- Justify the `pending_query_timeout` lower bound as protection against the worst kind of misconfiguration, where Pending Queries expire before upstream can answer and the cache silently never fills while reporting no error at all.
- Add no cross-field constraint between `max_pending_queries` and `max_entries`. Pending Queries scale with miss rate times upstream RTT; Cache Entries scale with working-set size.
- Treat `max_entries` as an upper bound on resident Cache Entries, where resident means published and not yet removed or replaced, whether or not the entry has expired. It is a resource ceiling, not a promise of that many live entries.
- Treat both `max_*` values as hard requirements and as actual runtime limits. A Backend that cannot provide them fails startup instead of silently reducing them, and greater physical capacity does not expand the Effective Config.
- Keep Negative Cache Admission in DNS Policy. When `cache_negative` is false, a valid NXDOMAIN or NODATA Response becomes a Bypass instead of a Cache Candidate; Cache Stores do not interpret this setting.
- Validate backend-neutral value rules in Config Loader, static Backend cache limits in `probe()`, and failures that depend on actual resource acquisition in `start()`.

Composition:

- Let each concrete Backend own and compose DNS Policy with its Cache Store. `EbpfNativeSession` remains a native adapter exposing only the narrow storage binding the eBPF Store needs, and neither component becomes a Host Runtime global service.
- Keep cache state local to one Shinku instance. The contract includes no distributed lookup, replication, shared warming, or consistency operations, and freshness is TTL-only for internal and public names alike.
- Require a live Query Correlation result before DNS Policy may construct a Cache Candidate. A standalone Response, including one whose network metadata suggests a DNS Service Endpoint, is insufficient for Cache Fill.
- Consume a Pending Query only after a non-expired record matches the reversed network endpoints, Transaction ID, and Question identity. A Question mismatch leaves the record available for a later complete match or expiration; the first complete match consumes it, so duplicate Responses cannot authorize another Cache Fill.
- Keep Pending Query failures Fail-open and outside Cache Store outcomes. Failure to retain or correlate an exchange skips its Cache Fill without blocking packet forwarding or changing existing Cache Entries.

Obligations created for later slices:

- 8D derives the eBPF arena slot size from `max_response_bytes` instead of the hardcoded `ARENA_ENTRY_SIZE`, so a smaller configured limit actually buys density.
- 8D verifies BPF verifier complexity for the fingerprint and the TTL patch loop at the start of the slice. If the combination does not fit, the documented fallback is the complete logical key as the BPF map key.
- 8D writes the hash secret into `.rodata` between skeleton open and load, which is the one place it extends the 8A Session signature. Maps are not pinned today; pinning them later would strand every entry fingerprinted under a previous secret.
- 8D implements the fingerprint once in a shared `static __always_inline` header compiled into both BPF and Host Runtime, defines the key struct once in the shared `types.h` with explicit padding and mandatory zero-initialization, and covers both with one focused test. Divergent implementations and uninitialized padding produce the same symptom, a permanent zero hit rate with no error.
- 8D and 8E add an integration test for the Cache Time Domain invariant: insert a short-lifetime entry from userspace and verify the XDP hit path flips from hit to miss at the expected boundary.
- 8E deletes the legacy rebuild path, including `flatten_name` and its thread-local flat buffer, together with the legacy TC-fallback storage path.

Testing:

- Value-type tests for `CanonicalDnsName` construction, lowercase normalization, the 255-byte limit, the root label, and compression-pointer rejection; for `CacheKey` inequality across every field including `CacheNamespace`; and for `CacheTime` arithmetic, comparison, and the compile failure that rejects a `steady_clock::time_point`.
- A reusable Cache Store conformance suite that every concrete Store must pass, covering the four Store Outcomes, expired-entry reuse as `Inserted`, `Rejected` leaving all entries hit-visible and unchanged, `WriteFailed` never publishing, incomplete patch plans producing `Rejected` rather than truncation, bounded cleanup with `removed_entries` and `more_work`, and the single-writer plus concurrent-cleanup contract. It asserts contract-observable behavior only and never an admission or eviction strategy.
- `FakeCacheStore`, which exists to prove the conformance suite is executable rather than to act as a reference implementation.
- Language-neutral Cache Hit vectors under `tests/vectors/cache_hit/`, plus a C++ reference applier. Coverage includes sub-second residence rounding, multi-section TTL aging with an Authority SOA, case-different question echo, Transaction ID rebinding, and both sides of the expiry boundary. Module 8D runs the same vectors against the XDP hit path.

See [ADR-0013](../../adr/0013-cache-contract-excludes-hit-path.md), [ADR-0014](../../adr/0014-verbatim-response-template.md), and [ADR-0015](../../adr/0015-keyed-fingerprint-cache-key.md).

### 8C: DNS Policy Engine

Purpose:

- Move DNS response parsing, validation, negative caching, TTL selection, CNAME behavior, and TC/malformed bypass decisions into a backend-neutral C++ policy engine.
- Classify each Query before correlation state is created. Only an eligible Cache Miss may establish a Pending Query; Bypass Queries never create state that could authorize a later Cache Fill.
- Construct a Cache Candidate only from a Response matched to a live Pending Query. Inherit the Cache Namespace and Query eligibility from that correlation result rather than inferring final cache identity from the Response payload alone.
- Classify an ECS-bearing Query and its correlated Response as ECS Pass-through. Do not perform a non-ECS Cache Key lookup for that Query and do not construct a Cache Candidate from that Response.
- Produce a verbatim Response Template plus its complete TTL patch plan on every cacheable non-ECS path, including CNAME responses. There is no normalization step and therefore no legacy raw-packet CNAME shortcut to retain: every cacheable path stores the same verbatim bytes. A Response that does not fit the Cache Response Limit is a Bypass.
- Own the Cacheable Query Profile checks, Cache Entry Lifetime derivation including the RFC 2308 negative rule, and the Bypass rules for truncation, `ARCOUNT != 0`, zero lifetime, and oversize, so that a Cache Candidate is valid by construction.

### 8D: eBPF Cache Store

Purpose:

- Adapt the eBPF map/arena storage implementation behind the backend-neutral cache store contract.
- Preserve seqlock, generation, slot-owner, admission metadata, eviction, and cleanup safety semantics.
- Use the BPF map update as eBPF Cache Publication after a complete stable arena write. Operations that can prevent publication occur before that update; post-publication bookkeeping cannot turn the successful write into `WriteFailed`.
- Update an existing Cache Key in its current eBPF slot under the write-safety protocol. Do not consume a replacement slot or invalidate an unrelated Cache Entry merely to refresh the same key.
- Correct the legacy XDP read protocol so generation validation occurs inside the seqlock read interval: map lookup, first stable sequence read, generation comparison, payload copy and patch metadata read, then matching second sequence read. This prevents a failed map update from exposing newly overwritten arena bytes through an old map value.
- Bypass immediately when the Query has `ARCOUNT != 0`; do not parse EDNS options on the MVP Cache Hit Path or let an ECS-bearing Query fall through to a non-ECS lookup.
- Define and verify a coherent reader snapshot protocol for any multi-field lookup metadata concurrently replaced by userspace. Repeated dereferences of a mutable BPF map value are not by themselves a consistency guarantee.
- Preserve the current Query Question Section on a Cache Hit. Copy the cached response header and the bytes after the question around the existing QNAME/QTYPE/QCLASS instead of overwriting and recopying the question; DNS Policy guarantees that the canonical question and wire length match the Cache Key.
- Patch the cached response Transaction ID with the current Query ID on every eBPF Cache Hit. The eBPF Store may retain the upstream ID physically, but it is never replayed as the ID of a later query.
- Obtain only the narrow native storage binding required from `EbpfNativeSession`; do not move cache policy into the Session.
- Build the physical key from a plaintext `CacheNamespace` plus a 128-bit keyed fingerprint over the canonical name, type, and class, using a keyed PRF with a per-process random secret. Implement the fingerprint once in a shared `static __always_inline` header and define the key struct once in the shared `types.h`, with explicit padding and mandatory zero-initialization.
- Derive the arena slot size from `max_response_bytes` rather than the hardcoded `ARENA_ENTRY_SIZE`.
- Verify BPF verifier complexity for the fingerprint and the TTL patch loop at the start of the slice. The documented fallback is using the complete logical key as the BPF map key.
- Write the hash secret into `.rodata` between skeleton open and load. This is the one place 8D extends the 8A Session signature. Do not pin maps without revisiting secret lifetime.
- Run the 8B Cache Store conformance suite and the 8B Cache Hit vectors against the eBPF Store and the XDP hit path.
- Add the Cache Time Domain integration test: insert a short-lifetime entry from userspace and verify that the XDP hit path flips from hit to miss at the expected boundary.

### 8E: Composition and Cutover

Purpose:

- Wire packet-ring callbacks through the backend-neutral DNS/cache policy and the eBPF cache store.
- Preserve the Query and Response network metadata required by Query Correlation instead of reducing a packet event to an unqualified DNS payload. Response metadata supplies a candidate endpoint; successful correlation supplies the authoritative Cache Namespace for Cache Fill.
- Require the eBPF MVP Cache Point to observe tuple-symmetric IPv4/UDP Query and Response traffic. Do not add conntrack integration or weaken correlation when NAT or proxying changes the endpoint identity between observations.
- Keep Pending Query state bounded and short-lived. Missing, expired, mismatched, or unavailable state suppresses Cache Fill for that exchange while Query and Response forwarding remain Fail-open.
- Refresh a Pending Query's `last_seen` time when XDP observes an identical eligible Cache Miss retransmission. TC evaluates expiration against that time before allowing a complete match.
- Validate Response Question identity in TC before deleting a complete Pending Query match and publishing its packet-ring event. A Question mismatch leaves the Pending Query live and does not enter the Host Runtime Cache Fill Path.
- Defer the eBPF Pending Query map choice until a focused benchmark compares an LRU hash against a bounded ordinary hash with explicit batch cleanup. Use the same configured capacity, timeout, and packet traces, and include cleanup CPU cost and correlation success under steady misses, capacity bursts, delayed Responses, and lost Responses.
- Activate `CacheConfig` behavior for the eBPF backend.
- Remove the legacy C parser/cache path when the new path has equivalent focused coverage.
- Start with synchronous Cache Fill for the MVP. Use benchmarks to decide whether a later bounded memory-pool queue is justified; if such a queue is introduced, saturation drops new fill work instead of blocking packet-ring consumption, preserving Fail-open behavior.

Verification:

- DNS parser tests.
- Cache store tests.
- DNS hash tests.
- Focused tests proving that every Query with `ARCOUNT != 0`, including ECS-bearing Queries, passes through without a non-ECS Cache Hit or Cache Fill.
- Query-correlation tests proving that Bypass, unsolicited, expired, and mismatched Responses cannot create Cache Entries; a matching eligible Cache Miss can; and Pending Query exhaustion remains Fail-open.
- Query-correlation tests proving that Question mismatch does not consume a still-live Pending Query, while the first complete match does and a duplicate Response cannot trigger another Cache Fill.
- A Pending Query representation benchmark comparing LRU eviction with explicit bounded cleanup using identical correctness semantics, capacities, timeouts, and traffic traces. Report throughput, p99 latency, CPU cost, correlation success, and pressure-induced skips or evictions.
- A benchmark matrix comparing a reference DNS service with and without its native cache against the same service with Shinku, including the combined-cache case. Report single-node throughput, p99 latency, and DNS-service CPU use for the same hot `A/IN` workload.
- eBPF Backend remains runnable throughout the cutover.
