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

- Accept IPv4/UDP standard `QUERY` opcode messages with exactly one `A/IN` question, `RD=1`, `CD=0`, `AD=0`, and `ARCOUNT=0`. A cacheable Response may contain CNAME or other upstream-selected RR types; Shinku does not resolve those records to prove that they answer the Question. `NXDOMAIN` and `NODATA` remain subject to Negative Cache Admission.
- Bypass every Query with an Additional Section, including EDNS, DNSSEC signaling, and ECS, plus `AAAA`, `SRV`, `TXT`, `MX`, `PTR`, multi-question messages, and TCP.
- Bypass a Response with `ARCOUNT != 0`, mirroring the Query rule. This also keeps the patch plan safe, because an OPT pseudo-record's TTL field carries an extended RCODE and flags rather than a TTL.
- Bypass a truncated Response. The legacy TC-fallback entry is not carried forward.
- Bypass a Response whose Cache Entry Lifetime would be zero. A zero TTL means "do not cache", and admitting it would consume Cache Capacity with an entry that can never be hit.
- Bypass a Response whose Cache Hit representation could exceed `max_response_bytes`, including fields generated or rebound for the current Query. Never truncate a Response for storage or emission, and never construct a Candidate for Store to reject.
- Later modules may broaden the profile, but every newly supported semantic that can change an answer must enter Cache Key identity or be normalized safely before it becomes cacheable.

Cache Key identity:

- Compose `CacheKey` from `CacheNamespace`, the canonical question name, question type, question class, and every other admitted semantic that can change the answer.
- Derive `CacheNamespace` from the original Query destination IPv4 address and UDP port, store both fields in host byte order, and keep it a field of the key rather than a Store parameter or a per-instance property. Packet-event composition converts explicitly named network-order fields into the Domain value. A Store may still shard its internal representation by namespace.
- Represent the canonical question name as a fixed-capacity, allocation-free DNS wire name: lowercase labels, no compression pointers, a terminating root label, and the DNS 255-byte limit.
- Treat the 32-bit FNV hash as neither the domain identity nor an acceptable Backend representation. Concrete Stores derive their own physical keys.
- Permit a physical key of plaintext network-order `CacheNamespace` (`__be32` destination IPv4, `__be16` destination port, explicit zeroed padding) plus a 128-bit keyed fingerprint over the canonical name, type, and class. The eBPF Store converts from the host-order Domain value; XDP copies packet fields directly without hot-path byte swaps. The fingerprint must be a keyed PRF with a per-process random secret; unkeyed 128-bit hashes are rejected because they restore an offline collision-construction primitive.

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
- Derive every Cache Entry Lifetime, including negative entries, from the minimum wire TTL across every retained RR. Trust the DNS Service Endpoint to have emitted the effective RFC 2308 negative lifetime in the Authority SOA TTL rather than parsing `SOA.MINIMUM` again.
- Classify `NXDOMAIN` from RCODE and classify `NOERROR` with an Authority `IN/SOA` as `NoData`; neither classification proves SOA relevance or CNAME terminal identity. A Response with no RR TTL cannot obtain a lifetime and is a Bypass.
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
- Validate `max_entries >= 1`, `max_pending_queries >= 1`, `max_response_bytes` within `[128, 512]`, and
  `pending_query_timeout` within `[100ms, 10s]` when constructing `CacheConfig`; Config Loader maps typed validation
  failures to field-specific diagnostics.
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
- 8D verifies BPF verifier complexity for the fingerprint and the TTL patch loop at the start of the slice. The MVP requires the selected implementation to pass on the current development host and ships no fallback implementation; failure reopens the physical-key or hit-path decision.
- 8D writes the hash secret into `.rodata` between skeleton open and load, which is the one place it extends the 8A Session signature. Maps are not pinned today; pinning them later would strand every entry fingerprinted under a previous secret.
- 8D implements the fingerprint once in a shared `static __always_inline` header compiled into both BPF and Host Runtime, defines the new physical structures once in a dedicated shared eBPF cache ABI header with explicit padding and mandatory zero-initialization, and covers both with one focused test. The new ABI does not extend legacy `types.h`, which remains coupled to the bridge deleted in 8E. Divergent implementations and uninitialized padding produce the same symptom, a permanent zero hit rate with no error.
- 8D and 8E add an integration test for the Cache Time Domain invariant: insert a short-lifetime entry from userspace and verify the XDP hit path flips from hit to miss at the expected boundary.
- 8E deletes the legacy rebuild path, including `flatten_name` and its thread-local flat buffer, together with the legacy TC-fallback storage path.

Testing:

- Value-type tests for `CanonicalDnsName` construction, lowercase normalization, the 255-byte limit, the root label, and compression-pointer rejection; for `CacheKey` inequality across every field including `CacheNamespace`; and for `CacheTime` arithmetic, comparison, and the compile failure that rejects a `steady_clock::time_point`.
- A reusable Cache Store conformance suite that every concrete Store must pass, covering the four Store Outcomes, expired-entry reuse as `Inserted`, `Rejected` leaving all entries hit-visible and unchanged, `WriteFailed` never publishing, incomplete patch plans producing `Rejected` rather than truncation, bounded cleanup with `removed_entries` and `more_work`, and the single-writer plus concurrent-cleanup contract. It asserts contract-observable behavior only and never an admission or eviction strategy.
- `FakeCacheStore`, which exists to prove the conformance suite is executable rather than to act as a reference implementation.
- Python-generated language-neutral Cache Hit vectors from `tests/vectors/cache_hit/generate.py`, plus a C++ reference applier. Meson writes the TOML contract artifact in the build directory. Coverage includes sub-second residence rounding, multi-section TTL aging with an Authority SOA, case-different question echo, Transaction ID rebinding, and both sides of the expiry boundary. Module 8D runs the same generated vectors against the XDP hit path.

Implementation result:

- Added the six header-only `shinku::cache` contract files under `src/cache/`: the explicit Cache Time domain, allocation-free canonical wire names, complete logical Cache Keys, borrowed Cache Candidates, the fill/cleanup-only Cache Store interface, and stable Store errors.
- Extended required `[cache]` configuration with `max_pending_queries` and `pending_query_timeout`, enforced the documented capacity and duration rules, and tightened `max_response_bytes` to `[128, 512]`. Benchmark and soak-generated Config Files now supply the required fields.
- Added focused value-type tests, a reusable Store conformance adapter and suite exercised by `FakeCacheStore`, and a standard-library Python DNS builder that generates four TOML Cache Hit vectors for the C++ reference applier.
- Kept the legacy C parser/cache bridge and the runnable eBPF Backend unchanged; no concrete production Store, hit lookup interface, Pending Query domain type, worker, queue, or Backend-specific dependency was introduced.
- `meson compile -C build` and the focused Cache Domain, Config Loader, and eBPF Backend tests pass. The full non-root Meson run passes 11 of 14 tests; the two arena tests still require root and the legacy C Cache Store test retains its documented no-map failures.
- `meson compile -C build tidy` still reports pre-existing Host Runtime and legacy C diagnostics; the new Cache Domain is header-only and compiles successfully through its focused test target.

See [ADR-0013](../../adr/0013-cache-contract-excludes-hit-path.md), [ADR-0014](../../adr/0014-verbatim-response-template.md), [ADR-0015](../../adr/0015-keyed-fingerprint-cache-key.md), and [ADR-0016](../../adr/0016-correlated-verbatim-packet-cache-policy.md).

### 8C: DNS Policy Engine

Purpose:

- Implement a backend-neutral Correlated Verbatim Packet Cache Policy: validate complete-message wire safety, correlated identity, TTL patchability, negative lifetime, and cache-profile admission while trusting the upstream DNS Service Endpoint's answer semantics.
- Implement a new bounded C++ DNS wire parser rather than adapting the legacy C parser. Keep the legacy parser unchanged until the 8E cutover deletes it.
- Separate structural wire parsing from DNS Policy judgment with an explicit `ParsedResponse` contract. Structural failures return `ParseError`; valid parsed facts are judged as either a `CacheCandidate` or a reasoned Bypass. Keep `classify_response()` as the production facade that composes both layers.
- Keep parsing and classification allocation-free and `noexcept`. `ParsedResponse` owns Header and canonical Question facts, an optional minimum RR TTL, and an Authority `IN/SOA` presence bit, and borrows the input message plus the active TTL-offset scratch range. No per-Answer or per-Authority fact arrays remain.
- Structurally traverse every Header-declared RR owner, fixed RR header, RDLENGTH, and RDATA boundary while retaining the original bytes. Record every non-OPT TTL offset and compute the minimum wire TTL, but do not interpret any RDATA. An RR owner scanner accepts ordinary labels with valid encoding and bounds or a complete two-octet compression pointer that terminates the encoded owner; it does not follow the pointer or validate its target.
- Treat a structurally valid compressed Response Question as `BypassReason::UnsupportedQuestionEncoding`. Cache Fill requires an uncompressed Question so Cache Hit substitution preserves message length, stored offsets, and compression-pointer targets.
- Require the cacheable Response Profile to have `QR=1`, standard `QUERY` opcode, `QDCOUNT=1`, `TC=0`, `ARCOUNT=0`, `RD=1`, `CD=0`, reserved `Z=0`, an `A/IN` Question, and base RCODE `NOERROR` or `NXDOMAIN`. Preserve `AA`, `RA`, and `AD` verbatim on Cache Hit. Additional must be empty. Structurally valid Answer and Authority RR types are not rejected merely because 8C does not interpret their semantics.
- Do not validate a CNAME chain, require a terminal A, reject unrelated Answer records, or prove that the upstream Response semantically answers the Question. Query Correlation and Question parsing establish cache identity; verbatim replay preserves the upstream answer.
- Classify `NXDOMAIN` from RCODE, `NOERROR` plus at least one Authority `IN/SOA` as `NoData`, and other admitted `NOERROR` responses as `Positive`. Apply Negative Cache Admission to the first two kinds. Lifetime is the minimum wire RR TTL for every kind; do not select an SOA or parse `SOA.MINIMUM`.
- Deliver the Response side only. `classify_response()` is the production entry point; there is no `classify_query()`, because the eBPF Backend classifies Queries in XDP to decide hit or miss and no Host Runtime object would call one.
- Keep Cacheable Query Profile membership on the Query side a backend-neutral rule set verified by shared vectors, in the manner of Cache Hit Semantics. Only a Query inside the profile may establish a Pending Query; Bypass Queries never create state that could authorize a later Cache Fill.
- Generate Query Eligibility vectors from the standard-library Python DNS packet builder under `tests/vectors/query_eligibility/`. Meson emits one Backend-neutral TOML contract artifact in the build directory; C++ tests and later Backend tests consume that generated artifact. Record wire bytes, expected eligibility, and eligible logical Question fields; let each Backend add its own packet envelope and test transport-specific behavior separately. Do not hand-maintain serialized DNS hex fixtures.
- Cover the Query Profile with one valid baseline and one-condition mutations. Do not add a production C++ Query classifier or put physical fingerprints, packet bytes, or Query-side Bypass reasons into the shared vector contract.
- Construct a Cache Candidate only from a Response matched to a live Pending Query. Inherit the Cache Namespace and Query eligibility from that correlation result rather than inferring final cache identity from the Response payload alone.
- Trust the TC Query Correlation result rather than passing Pending fingerprint or original Question into `classify_response()` for duplicate comparison. Still parse the Response Question independently for Response Profile checks, `CanonicalDnsName`, and `CacheKey`; do not use it as the root of a second Answer-resolution algorithm.
- Keep public cache-admission API in `src/cache/dns_policy.{h,cc}` and `src/cache/bypass_reason.h` under `shinku::cache`. Isolate wire parser internals in `src/cache/dns/` under `shinku::cache::dns`; do not introduce a general `src/dns/` module without a non-cache consumer.
- Let the wire parser construct `CanonicalDnsName` and extract Question type/class into `ParsedResponse`. Let DNS Policy add the correlated `CacheNamespace` and construct `CacheKey` only for an accepted Candidate; parser and Backend composition do not construct complete keys.
- Classify an ECS-bearing Query and its correlated Response as ECS Pass-through. Do not perform a non-ECS Cache Key lookup for that Query and do not construct a Cache Candidate from that Response.
- Represent ECS Pass-through only through existing Bypass behavior. Do not add ECS-specific C++ types or reasons and do not parse EDNS options: Query `ARCOUNT != 0` Bypasses before Pending creation, and an unexpected correlated Response with an Additional Section uses generic `AdditionalSectionPresent`.
- Test the wire parser, policy judgment, and production facade as separate deterministic layers. Add coverage-guided fuzz targets for the parser and facade, with termination, memory-safety, determinism, and successful-result offset invariants.
- Use Clang compiler-rt libFuzzer through an optional, separate Clang build. Add no fuzzing dependency or subproject, keep targets disabled by default, preserve the normal GCC/AddressSanitizer build, and retain minimized failures in a committed regression corpus.
- Produce a verbatim Response Template plus its complete TTL patch plan on every cacheable non-ECS path, including CNAME responses. There is no normalization step and therefore no legacy raw-packet CNAME shortcut to retain: every cacheable path stores the same verbatim bytes. A Response that does not fit the Cache Response Limit is a Bypass.
- Require the parser to consume every Question and RR declared by the DNS Header. Retain any remaining bytes inside the validated UDP payload as an opaque trailing suffix in the verbatim Response Template, matching dnsdist; do not parse that suffix as RRs or generate TTL offsets for it.
- Make each `DnsPolicy` instance single-caller and non-thread-safe. A successful `CacheCandidate` borrows the packet-event response bytes and the Policy's TTL-offset scratch, so Backend composition must call `CacheStore::store()` synchronously before the packet callback returns and before the next `classify_response()` call on that Policy instance. Give each concurrent worker its own `DnsPolicy`; do not add a mutex to the Cache Fill Path.
- Defer asynchronous Cache Fill. A future asynchronous path must copy the response and TTL offsets into an owned, bounded `FillWork` allocation before the packet callback returns; pool exhaustion drops only that fill attempt rather than extending the borrowed lifetime or blocking the callback.
- Own the Cacheable Query Profile checks, Cache Entry Lifetime derivation including the RFC 2308 negative rule, and the Bypass rules for truncation, `ARCOUNT != 0`, zero lifetime, and oversize, so that a Cache Candidate is valid by construction.

Design review findings:

- Resolved after superseding the old scratch design: `ParsedResponse` retains only Header and canonical Question facts, an optional minimum wire RR TTL, an Authority `IN/SOA` presence bit, the message view, and the active TTL-offset range. Separate expanded `ParsedAnswer` and `ParsedAuthority` arrays are removed with CNAME judgment.
- Resolved: keep the direct `classify_response(message, cache_namespace)` signature. Its API comment states that the message must come from a successful Query Correlation result; Backend composition and TC-to-Host integration tests enforce that precondition instead of an additional wrapper or capability type.
- Resolved: TC derives the exact DNS payload from UDP Length, publishes only complete payloads no larger than the 512-byte event capacity, and never truncates. The 8C facade alone applies configured `max_response_bytes`; the parser completely traverses every Header-declared RR and retains any remaining payload bytes as an opaque verbatim suffix.
- Resolved after superseding the resolver-style design: a CNAME-plus-negative Response remains one verbatim entry keyed by the original Question, but 8C does not follow the CNAME target or prove SOA ancestry. `NXDOMAIN` comes from RCODE, while `NOERROR` plus any Authority `IN/SOA` becomes `NoData`; all kinds use the minimum wire RR TTL.
- Resolved: wire-parser tests and fuzzing retain detailed `ParseError` values, while the production facade maps every structural failure to `BypassReason::MalformedResponse`. Public reasons remain Policy-level categories with a stable stage order rather than mirroring parser internals.
- Resolved in part: Query `AD=1` Bypasses before Pending creation because it can change a validating resolver's Response `AD` signal without appearing in the current Cache Key. A cacheable Response requires `RD=1`, `CD=0`, reserved `Z=0`, and `ARCOUNT=0`, and preserves `AA/RA/AD` verbatim. The old Answer/Authority RR-type whitelist is superseded; generic structurally valid RRs may be retained.
- Resolved: treat the correlated local DNS forwarder as trusted for DNS answer correctness, but validate every invariant required to construct and replay a `CacheCandidate`. Checks are limited to parser memory safety and the correctness of `CacheKey`, `CacheEntryKind`, lifetime, TTL patch plan, and verbatim-template boundaries; 8C does not reimplement recursive-resolver, DNSSEC, address-policy, or upstream-authority validation.
- Resolved: RR owner compression pointers are never followed because policy does not extract owner identity. The scanner requires only a complete two-octet pointer at a safe wire boundary and does not validate target range, direction, label boundaries, or cycles. The Response Question remains uncompressed because it supplies Cache Key identity and is rebound on Cache Hit.
- Resolved: logical `CacheNamespace` uses host order. Packet events and the physical eBPF key use explicitly named network-order fields; Backend composition and Store adapters own conversion, while XDP copies packet fields directly.
- Resolved: under RFC 2181, interpret any wire TTL with its high bit set as the entire value zero, not as the low 31 bits and not as `0x7fffffff`. The resulting minimum lifetime is zero, so the whole verbatim Response is a `ZeroLifetime` Bypass rather than a `ParseError`; `SOA.MINIMUM` is not parsed.
- Resolved: each `DnsPolicy` instance is single-caller and non-thread-safe. Backend composition consumes a successful borrowed Candidate synchronously through `CacheStore::store()` before the packet callback returns and before the next classification on that instance. Concurrent workers own separate Policy instances; asynchronous fill requires a future bounded owned-work abstraction.

Decision queue:

| # | Branch | Status |
| --- | --- | --- |
| 1 | C++ DNS Policy Query-side API versus Response-only API | Resolved: Response-only production API; Query eligibility uses shared vectors |
| 2 | `classify_response()` input type | Resolved after review: keep message plus Namespace and document successful Correlation as a caller precondition |
| 3 | Whether Bypass output carries a reason | Resolved: return stable `BypassReason` |
| 4 | Parser ownership and parse/judge separation | Resolved: new C++ parser with explicit `ParsedResponse`; legacy C is deleted in 8E |
| 5 | DNS compression-pointer validation strategy | Resolved: uncompressed Question; RR owners validate only encoded skip safety and never follow or validate pointer targets |
| 6 | Validation depth for CNAME chains, RCODE, `QR`, and opcode | Resolved: strict Header/Question profile and wire safety, but no CNAME-chain or Answer-relevance validation |
| 7 | Whether C++ repeats Response Question consistency validation after TC correlation | Resolved: trust TC correlation; C++ validates the Response Question but does not compare it to Pending identity again |
| 8 | Source directory layout and C++ namespace | Resolved: public Cache Policy in `shinku::cache`; parser internals in `src/cache/dns/` and `shinku::cache::dns` |
| 9 | Query Eligibility shared-vector schema and coverage | Resolved: Python-generated Backend-neutral DNS message TOML artifact with Backend-specific packet wrapping and single-condition coverage |
| 10 | Ownership of `CacheKey` and `CanonicalDnsName` construction | Resolved: parser constructs canonical Question identity; Policy combines it with correlated Namespace into `CacheKey` |
| 11 | Type-level representation of ECS Pass-through | Resolved: no ECS-specific type or reason; use generic Additional Section Bypass behavior |
| 12 | Parser, policy, fuzz, vector, and composition test strategy | Resolved: layered deterministic tests plus optional Clang libFuzzer targets and committed regressions |
| 13 | Concrete `ParsedResponse` and parser-scratch representation | Resolved: Header/Question, optional minimum wire TTL, Authority IN/SOA presence, message view, and TTL-offset scratch only |
| 14 | Complete-message framing across TC, ring event, and parser | Resolved: complete UDP-length event, complete declared-RR traversal, and opaque verbatim retention of trailing bytes |
| 15 | Negative SOA relevance, multiplicity, Authority NS interaction, and lifetime composition | Resolved: no SOA selection or RDATA parse; Authority IN/SOA signals NoData and all kinds use minimum wire RR TTL |
| 16 | `ParseError` to `BypassReason` mapping, stable reason set, and precedence | Resolved: detailed internal ParseError, facade MalformedResponse, Policy-level reasons, stage-order precedence |
| 17 | Remaining Query/Response flags and exact RR schema | Resolved: flags and empty Additional remain strict; Answer/Authority use generic RR traversal instead of a semantic type whitelist |
| 18 | `CacheNamespace` byte order and boundary conversion | Resolved: host-order Domain, network-order event/physical key, explicit Backend-boundary conversion, no XDP byte swap |
| 19 | TTL values above RFC 2181's 31-bit maximum | Resolved: interpret as zero and apply whole-template ZeroLifetime Bypass |
| 20 | `DnsPolicy` concurrency and borrowed-result lifetime | Resolved: one Policy per concurrent worker; synchronously store before callback return and next classification; future async fill must materialize bounded owned work |
| 21 | Identity of a CNAME-bearing negative result | Resolved: one combined verbatim entry under the original Question; terminal CNAME identity is not parsed or validated |
| 22 | Trust boundary and validation depth for upstream Responses | Resolved: trust DNS answer correctness; validate only Cache Candidate construction/replay invariants |
| 23 | Correlated verbatim packet-cache positioning | Resolved: no CNAME-chain or Answer-relevance validation; retain strict wire, identity, TTL, and negative-lifetime checks |
| 24 | dnsdist-compatible admission semantics | Resolved: adopt its correlation and opaque-Answer model, but require a complete fill-time TTL patch plan rather than best-effort partial parsing |

RFC basis for negative-response decisions:

- [RFC 2308 sections 1, 2.1, and 2.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-2) permit CNAME records in negative Answers and define the terminal CNAME target as the negative `QNAME`. Shinku deliberately does not reconstruct that resolver fact: it retains one correlated verbatim response under the original Question and must derive negative admission from bounded packet facts.
- NXDOMAIN is distinguished from a referral by RCODE regardless of Authority NS/SOA contents; for NODATA, an Authority SOA distinguishes a negative response from an NS-only referral. SOA plus NS is a valid type-1 negative response, although authoritative servers are recommended to emit type 2 for compatibility.
- [RFC 2308 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5) define negative TTL as `min(SOA.TTL, SOA.MINIMUM)` and require the authoritative sender to place that effective value in the SOA TTL of the negative response. Like dnsdist, Shinku trusts the correlated DNS Service Endpoint's emitted wire TTL instead of parsing SOA RDATA again.
- [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8) limits positive TTL values to `0x7fffffff` and requires a received TTL with the high bit set to be treated as zero. Shinku applies that interpretation before computing the minimum whole-template lifetime.
- [RFC 1034 section 4.2.1](https://www.rfc-editor.org/rfc/rfc1034.html#section-4.2.1) describes one SOA RR at a zone origin, and [RFC 2181 section 5.5](https://www.rfc-editor.org/rfc/rfc2181.html#section-5.5) calls an SOA RRset a single-RR RRset. Multiple SOAs are therefore not an ordinary negative-response case that the MVP must reconcile.
- RFC resolvers can cache and expire the CNAME, negative SOA, and other RRsets independently. Shinku's minimum across every retained RR is an additional consequence of storing and replaying one verbatim Response Template: the whole entry must expire when any retained component can no longer be replayed safely.

RFC basis for Header-flag decisions:

- [RFC 1035 section 4.1.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1) requires the Response to copy `RD` from the Query and requires the then-reserved `Z` field to be zero. Later standards assigned two of those bits to `AD` and `CD`, leaving one reserved bit that must remain zero.
- [RFC 4035 section 3.2.2](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.2) requires a security-aware name server to copy `CD` from Query to Response.
- [RFC 6840 sections 5.7 and 5.8](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7) defines Query `AD=1` as interest in authenticated-data signaling and recommends setting Response `AD` only when the request had `DO=1` or `AD=1`. Query `AD` can therefore change a Response even when the Query has no EDNS Additional Section.

Implementation result:

- Added the allocation-free `DnsPolicy` facade, stable public `BypassReason`, internal `ParsedResponse`/`ParseError` contracts, generic DNS wire parser, and separate response-policy judgment under `src/cache/`.
- The parser completely traverses Header-declared Questions and RRs within the 512-byte event bound, retains trailing bytes, records all non-OPT TTL offsets, detects Authority `IN/SOA`, applies RFC 2181 high-bit TTL handling, and never interprets RDATA or follows RR owner compression pointers.
- The policy enforces the correlated Response Profile, constructs `CacheKey` from the canonical Question plus correlated host-order `CacheNamespace`, classifies packet-cache `Positive`/`NxDomain`/`NoData`, applies Negative Cache Admission, and returns a borrowed `CacheCandidate` with minimum whole-template lifetime.
- Added a standard-library Python generator for 19 language-neutral Query Eligibility vectors covering the valid baseline and one-condition mutations for direction, opcode, section counts, flags, type/class, EDNS/DO/ECS, compressed or malformed QNAME, and truncation. It builds Header, Question, RR, OPT, and ECS wire structures with network-order serialization and validates the generated set before Meson writes one TOML artifact. The C++ test consumes that generated artifact and validates the shared schema; real Backend consumption remains 8D/8E work.
- Added layered Catch2 tests for parser, policy, facade, and fuzz-corpus decoding behavior, including opaque unusual Answers, trailing bytes, malformed boundaries, the 45-offset maximum, negative classification, zero lifetime, retained response flags, Additional Section bypass, LF/CRLF hex seeds, stable Bypass reasons, and content-based equality for borrowed parser and Candidate views. The target passes 318 assertions in 22 test cases; the existing Cache Domain target passes 170 assertions in 9 test cases.
- Added optional `-Ddns_fuzzing=true` Clang compiler-rt libFuzzer targets for the parser and facade, plus committed valid and malformed seed corpora. A separate non-default build compiles both targets, and 1,000-run smoke tests pass for each with AddressSanitizer and UndefinedBehaviorSanitizer enabled.
- The complete default build, strict `-Wall -Wextra -Wpedantic -Werror` syntax check, focused clang-tidy run, and `git diff --check` pass. LeakSanitizer remains incompatible with the ptraced execution environment, so focused Catch2 verification disables leak detection; all test assertions pass.
- The legacy C parser/cache bridge remains the active production data path until 8E. Compiling the new sources into `shinku` verifies integration without changing BPF attach/detach, packet polling, cleanup scheduling, signal handling, or shutdown behavior.

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
- Build the physical key from a plaintext network-order `CacheNamespace` plus a 128-bit keyed fingerprint over the canonical name, type, and class, using a keyed PRF with a per-process random secret. Implement the fingerprint once in a shared `static __always_inline` header and define the new physical ABI once in a dedicated shared header, using `__be32`/`__be16`, explicit padding, and mandatory zero-initialization. Do not add the new ABI to legacy `types.h`, because that header remains coupled to the bridge deleted by 8E. Convert the host-order Domain value only in the Store adapter; XDP uses packet address and port fields directly.
- Derive the arena slot size from `max_response_bytes` rather than the hardcoded `ARENA_ENTRY_SIZE`.
- Verify BPF verifier complexity for the fingerprint and the TTL patch loop at the start of the slice. The MVP supports only the current development host and ships no verifier fallback path; rejection on that host reopens the physical-key or hit-path design before implementation continues. A wider development-time supported-kernel matrix is deferred beyond the MVP.
- Write the hash secret into `.rodata` between skeleton open and load. This is the one place 8D extends the 8A Session signature. Do not pin maps without revisiting secret lifetime.
- Run the 8B Cache Store conformance suite and the 8B Cache Hit vectors against the eBPF Store and the XDP hit path.
- Add the Cache Time Domain integration test: insert a short-lifetime entry from userspace and verify that the XDP hit path flips from hit to miss at the expected boundary.

Decision queue (in dependency order):

| # | Decision point | Why it must be resolved before implementation |
|---:|---|---|
| 8D-1 | Arena storage shape and runtime `max_response_bytes` | Resolved: use one raw arena slab with an aligned runtime slot stride derived from per-entry metadata plus the configured response limit. XDP and Host Runtime use the same checked `base + index * stride` calculation; a verifier prototype gates the design before implementation. |
| 8D-2 | Capacity and startup satisfiability formula | Resolved: remove `ebpf.arena_pages` from Config Schema and derive the exact arena map page count from `max_entries`, the resolved slot layout, system page size, and required control/alignment bytes. Cache map capacity is set to configured `max_entries`; kernel resource acquisition failures remain `start()` failures. |
| 8D-3 | Physical Cache Entry and map-value layouts | Resolved: use a self-contained seqlocked arena slot for all hit-visible metadata, complete TTL patch plan, and Response bytes; keep the BPF map value as a 16-byte Cache Publication handle containing slot index and 64-bit generation. The 32-byte slot Header and packed active-region ordering are fixed below. Immutable copy-on-write slots with RCU/QSBR reclamation are deferred as a future read-path optimization, not used by the MVP. |
| 8D-4 | Cache Time representation | Resolved: use `CLOCK_BOOTTIME` in Host Runtime and `bpf_ktime_get_boot_ns()` in BPF so suspend consumes DNS TTL. Persist both `stored_at_ns` and `expires_at_ns`. The trusted TC/Policy path supplies a positive `uint32_t`-derived lifetime and representable BOOTTIME, so Store computes expiry directly; XDP compares expiry and derives elapsed nanoseconds from insertion time. |
| 8D-5 | 128-bit keyed fingerprint algorithm and secret lifecycle | Resolved: use the SipHash-2-4 128-bit output variant over canonical name, type, and class, with plaintext network-order Namespace in the physical key. `EbpfBackend::start()` obtains the per-process secret with `getrandom()`, passes the same typed value to skeleton `.rodata` and Store construction, fails startup on entropy failure, never logs or persists it, and permits fixed-secret test injection. The MVP ships no alternate physical-key implementation; verifier rejection on the development host reopens this decision. Two domain-separated SipHash-2-4 outputs and the complete logical key remain design candidates, not runtime fallbacks. |
| 8D-6 | Coherent XDP snapshot protocol | Resolved: copy the seqlocked arena slot into one per-CPU scratch-map value, validate matching even sequence and generation plus all bounds while the Query packet is untouched, and only then construct the Response from scratch. A validation conflict returns `XDP_PASS` safely. Benchmark the extra lookup and copy; immutable slots plus per-CPU QSBR remain the later optimization path if this cost is material. |
| 8D-7 | Store state machine and Cache Publication rollback boundary | Resolved: use invalidate-first publication with construction-time rollback scratch. Same-key Update restores its old slot if map publication fails; Replacement deletes its victim key before overwrite and may lose that victim on failed candidate publication, as permitted by the Store error contract. Empty/expired failures return the slot to free state. Use a 64-bit generation and advance private owner/cursor state only at the defined transition. |
| 8D-8 | MVP Store Admission and victim selection | Resolved for MVP: use empty/cleanup-reclaimed free slots first, then deterministic round-robin; same-key Update does not advance replacement. A selected expired victim yields `Inserted`, while a live different victim yields `Replaced`. Do not carry legacy sketch/recent/hot-cold state. Benchmark backlog `PERF-8D-1` owns any later CLOCK or TinyLFU decision. |
| 8D-9 | `store()` versus `cleanup()` synchronization and owner index | Resolved for MVP: one Store-owned mutex serializes the single Store caller and bounded cleanup caller around owner index, free-list, cursor, map, and arena transitions; it never enters XDP. Benchmark backlog `PERF-8D-2` determines whether measured contention justifies finer-grained synchronization. |
| 8D-10 | Bounded cleanup traversal | Resolved for MVP: scan a capacity-sized userspace owner index with a persistent cursor and bounded slots-per-call sweep. Owner/map agreement is an internal invariant, so cleanup directly erases an expired owner's physical key; any erase error leaves the owner unchanged and returns `CleanupFailed`. Return `more_work` until one capacity-wide sweep completes. Benchmark backlog `PERF-8D-3` compares this baseline with a generation-filtered expiration heap later. |
| 8D-11 | `EbpfNativeStorageBinding` boundary and lifetime | Resolved and extended by 8E: retain `EbpfNativeSession` as sole owner of skeleton, maps, arena mapping, links, and rings. Module 8E wraps the checked cache layout and secret with Pending capacity/timeout in `EbpfSkeletonConfig`; `prepare_skeleton(config)` returns a move-only composite `EbpfNativeBinding` containing the original non-owning cache-map/arena loan and a narrow non-owning Pending-map loan. It exposes no skeleton or layout authority. Store and Cleaner do not duplicate fds or remap arena memory. Backend member order plus explicit partial-start/shutdown reset destroys both borrowers before Session release. |
| 8D-12 | Verifier feasibility gate and fallback trigger | Resolved for MVP: load-test the selected keyed fingerprint and worst-case 45-offset TTL patch loop separately, then the combined production path with runtime stride, snapshot validation, and packet rewriting. The verifier-approved form uses `bpf_loop()` callbacks for active snapshot copies and TTL patching, and XDP load/store byte helpers for bounded frame copies; direct nested bounded loops exceeded the analyzed-instruction limit. The only required target is the current development host. Ship one production BPF object and no automatic or runtime fallback; verifier rejection reopens the design. A declared multi-kernel development-time support matrix is tracked as deferred feature `DF-1`. |
| 8D-13 | Concrete Store and XDP contract-test harness | Resolved: use three layers. Unprivileged tests run the real `EbpfCacheStore` state machine over heap-backed arena memory and injected fake map operations, including deterministic update/delete failures. Privileged verifier tests use real maps, arena, the production XDP program, `bpf_prog_test_run_opts()`, generated Cache Hit vectors, and Cache Time boundary cases. Network-namespace integration separately verifies real attachment, packet traffic, lifecycle, and envelope behavior. |

Additional resolved storage details:

- Derive each Store's fixed TTL-offset capacity from `max_response_bytes` using a checked DNS wire-format upper bound; retain 45 only as the 512-byte worst case rather than reserving it for every configuration.
- Treat binding/layout validity as an internal composition invariant. The checked layout factory and Session preparation are the only production sources; Store construction uses debug assertions instead of a second production validation/error path. Store operations trust Cache Candidate semantics and validate only concrete layout capacity plus mutable slot contents where they can vary at runtime.
- Use `Header | actual Response | alignment | actual TTL offsets | unused capacity` inside each fixed-stride slot. XDP derives and validates the dynamic offset-table position before copying; per-CPU scratch may remain fixed-array based. This keeps active arena data sequential and the Response Template contiguous while preserving fixed Capacity and stride. The combined verifier prototype gates the additional bounded pointer arithmetic.
- Fix the shared slot Header at 32 bytes: `u32 sequence`, `u16 response_size`, `u16 ttl_offset_count`, `u64 generation`, `u64 stored_at_ns`, and `u64 expires_at_ns`, with compile-time ABI assertions. Sequence remains 32-bit for one bounded snapshot; publication generation is 64-bit for slot-reuse identity.
- Do not clear inactive slot tails. Write and snapshot only the bounded active region, and poison unused bytes in tests to prove they cannot be emitted or interpreted.
- Fix the map publication value at 16 bytes: `u32 slot_index`, zeroed `u32 reserved`, and `u64 generation`. Insert and Replacement publish with `BPF_NOEXIST`; same-key Update publishes with `BPF_EXIST`.
- Allocate nonzero 64-bit generations monotonically under the Store mutex. Skip zero on theoretical unsigned wrap without adding an operational failure path.
- Put generation comparison, Header bounds, active Response/offset copying, and both ordering barriers inside one even, unchanged seqlock interval. A second map lookup is not a snapshot protocol.
- Use one fixed worst-case `BPF_MAP_TYPE_PERCPU_ARRAY` scratch value per CPU, with a 512-byte Response array and 45-offset array regardless of the configured Response Limit.
- Use `bpf_loop()` callbacks to copy only the active Response and TTL-offset plan into per-CPU scratch and to apply the active TTL patch plan. Use `bpf_xdp_load_bytes()` and `bpf_xdp_store_bytes()` for bounded variable-length frame copies. These helpers avoid verifier state multiplication while retaining active-length work; zero-length input skips the load helper and a zero-length cached Response is a fail-open miss.
- Complete expiry, offset validation, TTL aging, and response preparation in validated scratch before changing packet length or bytes. Every pre-mutation failure returns `XDP_PASS` with the original Query intact.
- Use one aligned atomic Host writer helper and a verifier-proven BPF reader barrier protocol for the shared 32-bit sequence; do not treat `volatile` alone as synchronization.
- Bound each cleanup call to 256 owner slots. The worker immediately continues while `more_work` is true and checks its stop token between batches; this remains a private Store constant.

Final 8D implementation decisions:

| # | Decision point | Why it remains open |
|---:|---|---|
| 8D-I1 | Owner index and reclaimed-slot allocator representation | Resolved: use one capacity-sized Host `SlotRecord` array with physical key, nonzero occupied generation, expiry, and `next_free`. A monotonic `next_unused_slot` represents the never-used suffix; `free_head` forms an intrusive Host-only free list for reclaimed or failed-publication slots. Allocation and return are O(1), and no separate occupied boolean/vector/bitmap enters the design. |
| 8D-I2 | Owner/map divergence policy | Resolved: owner/map agreement is an internal invariant, not an operational recovery case. Cleanup directly erases the expired owner's key without a pre-delete lookup; any erase error leaves owner state unchanged and returns `CleanupFailed`. Same-key lookup uses debug assertions for slot/generation agreement. No automatic reclaim, reconstruction, or release-build repair path is added. |
| 8D-I3 | Store construction allocation failure | Superseded by the trusted internal-call rule: Store construction uses ordinary allocation and does not add a local `bad_alloc` adapter. Allocation exceptions follow the existing process-level fatal exception boundary; runtime Store operations remain allocation-free and add no exception guards. |

Additional allocation decision:

- Keep one inline worst-case rollback scratch buffer in `EbpfCacheStore`; it requires no heap allocation and copies only the old active slot region.
- Do not add a process-global memory pool. Cache Hit, synchronous Cache Fill, and cleanup remain allocation-free after successful startup. Ordinary startup allocation failures follow the process-level fatal exception boundary. Future asynchronous Fill and DPDK packet memory require purpose-specific bounded pools rather than this module owning a general allocator.

Implementation status (in progress):

- Added dedicated shared C ABI and shared SipHash-2-4-128 headers for the 24-byte physical key, 16-byte publication, 32-byte slot Header, fixed BPF layout, and per-CPU scratch. Host tests cover the published SipHash-128 reference vectors and compile-time ABI assertions.
- Added checked `EbpfCacheStorageLayout` derivation, move-only non-owning `EbpfNativeStorageBinding`, the fd-backed `EbpfCacheMap` adapter, `getrandom()` secret acquisition, and the real `EbpfCacheStore` state machine. The Store implements same-slot Update rollback, invalidate-first Replacement, O(1) free-slot reuse, deterministic round-robin admission, monotonic generations, atomic Host seqlock writes, and 256-slot cleanup sweeps.
- Added unprivileged tests over heap-backed arena memory and an injected deterministic fake map. They cover layout density and the 45-offset bound, inactive-tail preservation, Update rollback, failed Insert and victim invalidation, map lookup failure, cleanup retry, free-list reuse, and concurrent Store/cleanup serialization.
- Added three standalone BPF verifier-gate programs for keyed fingerprinting, a complete 45-offset patch loop, and the combined runtime-stride/seqlock/scratch/TTL/packet-rewrite path. A privileged cross-boundary test loads them, writes through the real `EbpfCacheStore` into the skeleton arena and hash map, then executes the combined XDP program with `bpf_prog_test_run_opts()`.
- Clang compilation and skeleton generation pass on the development host. The privileged gate passes on Linux `7.1.5-200.fc44.x86_64` with Clang `22.1.8`: all three programs load, the Host Store publishes through the real hash map and arena, and `bpf_prog_test_run_opts()` returns the expected XDP Cache Hit. The related Cache Domain, DNS Policy, eBPF Store, Backend Runner, and eBPF Backend assertions also pass; Meson's LeakSanitizer exit scan remains incompatible with the ptrace execution environment, so focused runs disable leak detection while retaining the other sanitizer checks.
- Generated Cache Hit vectors and the before/at-expiry Cache Time boundary cases are not yet connected to the privileged harness. They remain the final 8D verification work and prevent marking the slice complete.
- The legacy bridge remains the active production packet path, so `ebpf.arena_pages`, the current Session signature, and the attached legacy XDP program are intentionally unchanged in this implementation step. 8E composition will replace those together, return the borrowed binding from Session, install the new `.rodata` layout/secret, remove the old Config field, and delete the old bridge without a dual-write interval. This keeps the eBPF Backend runnable while 8D is verified in isolation.

### 8E: Composition and Cutover

Purpose:

- Wire packet-ring callbacks through the backend-neutral DNS/cache policy and the eBPF cache store.
- Derive DNS event length from the validated UDP Length. Publish only a complete payload that fits the 512-byte ring-event capacity, never cap or truncate a larger Response, and let 8C apply the configured Cache Response Limit to complete events.
- Preserve the Query and Response network metadata required by Query Correlation instead of reducing a packet event to an unqualified DNS payload. Response metadata supplies a candidate endpoint; successful correlation supplies the authoritative Cache Namespace for Cache Fill.
- Require the eBPF MVP Cache Point to observe tuple-symmetric IPv4/UDP Query and Response traffic. Do not add conntrack integration or weaken correlation when NAT or proxying changes the endpoint identity between observations.
- Keep Pending Query state bounded and short-lived. Missing, expired, mismatched, or unavailable state suppresses Cache Fill for that exchange while Query and Response forwarding remain Fail-open.
- Refresh a Pending Query's `last_seen` time when XDP observes an identical eligible Cache Miss retransmission. TC evaluates expiration against that time before allowing a complete match.
- Validate Response Question identity in TC before deleting a complete Pending Query match and publishing its packet-ring event. A Question mismatch leaves the Pending Query live and does not enter the Host Runtime Cache Fill Path.
- Defer the eBPF Pending Query map choice until a focused benchmark compares an LRU hash against a bounded ordinary hash with explicit batch cleanup. Use the same configured capacity, timeout, and packet traces, and include cleanup CPU cost and correlation success under steady misses, capacity bursts, delayed Responses, and lost Responses.
- Activate `CacheConfig` behavior for the eBPF backend.
- Remove the legacy C parser/cache path in the atomic production cutover once the new Contract has its required layered correctness evidence. Legacy behavior and tests are not an equivalence baseline.
- Use synchronous callback-local Cache Fill as the fixed MVP Contract. Performance results establish a baseline but do not trigger an asynchronous redesign in Module 8; any later bounded `FillWork` design is a separate post-MVP decision.

Decision queue (current status, in dependency order):

| # | Decision point | Why it must be resolved before implementation |
|---:|---|---|
| 8E-1 | XDP Query Eligibility parser and shared-vector consumer | Resolved: XDP completes Query Eligibility before any cache lookup or Pending mutation. All ineligible vectors prove zero cache lookup and zero Pending side effects. An eligible Query is parsed once into one shared result consumed by Cache lookup and, on a miss, Pending creation. |
| 8E-2 | Pending Query physical key and value | Resolved: trust the DNS Forwarder not to concurrently reuse one complete network tuple plus Transaction ID for different Questions. Use one Query-oriented network-order key containing Query source/destination IPv4 and UDP ports plus Transaction ID, with explicit zeroed padding and no ifindex, protocol, Question identity, or duplicated Cache Namespace. TC reverses the Response tuple; Query destination supplies the authoritative Cache Namespace. The 24-byte value contains the shared keyed 128-bit fingerprint of canonical QNAME, QTYPE, and QCLASS followed by the aligned atomic state/time word. Complete-Question storage is rejected. The combined path owes a verifier load test during implementation; rejection reopens the design without a weaker fallback. |
| 8E-3 | Pending map representation | Resolved for MVP: use one bounded `BPF_MAP_TYPE_HASH` with bounded Host cleanup. This is a conservative MVP choice rather than a claim of global optimality. LRU is not a production candidate or an 8E benchmark gate because capacity-pressure eviction can remove Claimed tombstones before timeout and permit duplicate Fill. Reopening LRU requires evidence of material HASH cleanup harm plus an explicit future decision about that semantic boundary. `PERF-M8-1` whole-system evidence remains required; the paused benchmark backlog is unchanged. |
| 8E-4 | Atomic retransmission refresh and single-consumer correlation | Resolved: one aligned 64-bit word stores `Claimed` in its high bit and `bpf_ktime_get_boot_ns()` `last_seen` in its low 63 bits. XDP refresh and TC claim use compare-and-swap on the whole word; a mismatch leaves Active state unchanged and at most one matching Response obtains authorization. Unrepresentable boot time fails open. The production HASH path owes verifier load tests with fixed-bounded retry during implementation; rejection reopens the design. |
| 8E-5 | Pending consumption, tombstones, and cleanup | Resolved for MVP: after validation and Pending lookup, reserve an unpublished ring record and copy the complete payload before CAS claiming the observed Active state. Reserve/copy/CAS failure discards the record and leaves Pending unchanged; only the claim winner submits. After submit, Claimed remains a consumed-exchange tombstone until Pending Query Timeout cleanup; XDP cannot refresh, overwrite, or reactivate it, and TC cannot authorize another Fill from it. The Response path never deletes it. A Backend-owned `PendingQueryCleaner` performs bounded HASH lookup/recheck/delete with no BPF reclaimer. A concurrent refresh after the final recheck may be deleted, losing one Fill while forwarding and Cache correctness remain intact; this narrow Fail-open race is accepted. Each batch inspects at most 256 snapshots through `bpf_map_lookup_batch()` with a persistent opaque cursor, resets at terminal/error, and checks stop/fair rotation between batches. Tests must cover both sides of the race, tombstone deletion, delete failure, cursor continuation, duplicates, same-key reuse, and batch stop latency. Exact event framing remains 8E-6. |
| 8E-6 | Correlated ring-event ABI and complete-message framing | Resolved: use one fixed 528-byte event containing a 16-byte header (native-endian 64-bit BOOTTIME Response Observation Time, network-order Query-destination IPv4 and UDP port, and 16-bit response size) plus a 512-byte payload capacity, with shared size/offset assertions. After complete validation and before reserve, TC captures `bpf_ktime_get_boot_ns()`. It reserves the fixed record, copies only a complete validated DNS payload in `[12, 512]`, and never truncates or clears the inactive suffix. The suffix is visible in the raw callback span with unspecified bytes but is non-semantic: the sole decoder may expose only validated fields and the active prefix, and may not read, copy, hash, serialize, log, diagnose, or propagate the tail. Poisoned-tail tests enforce independence. No fingerprint, complete Pending key, ifindex, or Cache Entry metadata crosses the ring. Store persists observation time as `stored_at`, computes expiry from it, uses a separately read admission `now` for exhaustion and victim liveness, and rejects same-key observations that are not strictly newer. Fixed-record pressure enters `PERF-8E-2`; dynptr records remain a measured future alternative. |
| 8E-7 | Packet-envelope, topology, and XDP commit boundary | Resolved: only untagged, unfragmented IPv4/UDP datagrams with `IHL == 5`, exact consistent lengths, complete captured bytes, port 53 in the correct hook direction, and a strictly reversed tuple may have Cache or Pending side effects. XDP additionally requires valid unicast address classes before lookup/mutation; TC relies on exact reverse correlation. Input checksums are not validated. A Cache Hit fully constructs an at-most-540-byte Ethernet/normalized-IPv4/UDP/DNS frame in per-CPU scratch, including aged TTLs, Question/ID semantics, recalculated lengths and IPv4 checksum, and zero IPv4 UDP checksum. `bpf_xdp_adjust_tail()` is the mutation commit boundary: any pre-adjust or adjust failure returns `XDP_PASS`; after success, XDP revalidates bounds and performs one complete `bpf_xdp_store_bytes()`. Post-adjust bounds/store failure returns `XDP_DROP`, never `XDP_PASS`; success returns `XDP_TX`. No incremental mutation or rollback is allowed. Directed broadcast is not detected without a subnet mask, while VLAN-aware identity is deferred as `DF-12`. |
| 8E-8 | Packet callback, bounded polling, and Backend composition ownership | Resolved: `EbpfBackend` owns a typed packet-event consumer together with `DnsPolicy` and `EbpfCacheStore`; packet-ring creation gives `EbpfNativeSession` a non-owning consumer reference for exactly the ring lifetime. Each Backend poll drains the optional log ring nonblocking, then Session first performs nonblocking `ring_buffer__consume_n(..., 64)` and, only when empty, waits on the packet ring epoll fd before one more bounded consume; the log ring never inherits packet timeout. Timeout/interruption produces `NoWork`; other wait/consume errors produce `PollFailed`; `[1, 64]`, including a full batch with backlog, is normal `WorkDone`. Runner checks Stop Condition before the next poll. The always-zero trampoline synchronously delivers a callback-scoped raw 528-byte ABI span to the Backend decoder, which constructs `CacheNamespace` and Response Observation Time. Backend classifies, reads Store Admission Time, and calls `store(candidate, observed_at, now)` before callback return. TC, the decoder, and `DnsPolicy` are trusted to supply representable BOOTTIME values and a complete bounded Candidate; Store handles only TTL exhaustion during queueing and non-newer same-key observations. No queue, event copy, direct struct cast, Session-side ABI/domain decoding, Policy/Store ownership, callback stop signal, or extra PollStatus is introduced. |
| 8E-9 | Startup, cleanup-worker, and shutdown ordering after cutover | Resolved: before attach, Backend computes layout, generates the secret, and builds typed `EbpfSkeletonConfig` with Pending capacity and checked nanosecond timeout. `prepare_skeleton(config)` sizes native maps, writes fixed-width `.rodata`, loads, and returns one move-only composite binding. Backend moves its cache-map/arena loan into Store and Pending-map loan into `PendingQueryCleaner`, then constructs Policy/consumer and the log ring. It preserves XDP retry, TCX-to-legacy fallback, packet-ring creation, and finally starts one Backend-owned CleanupWorker borrowing Store and cleaner. That worker maintains independent deadlines, executes one bounded batch at a time, and alternates when both report `more_work`; Cache cleanup retains `cleanup_interval`, while Pending cleanup runs every `pending_query_timeout / 2` in at-most-256-record batches. Normal stop and every partial-start cleanup join the worker, close the packet ring, destroy consumer/Policy, destroy Store/cleaner, and only then aggregate-release Session resources. Session owns all native handles but no cleanup policy; accessors, split ownership, a second cleanup thread, shared cadence, post-attach/lazy Host construction, and aggregate release before borrower destruction are rejected. |
| 8E-10 | Fill-path Bypass/Rejected/error handling before Module 10 | Resolved: the libbpf packet-sample trampoline always returns zero. ABI decode, Cache Time, Store, and cleanup failures abandon only the current Fill or cleanup sequence and never alter ring poll results, accumulate toward Backend failure, or become `BackendError`; cleanup retries after the next interval. Only packet-ring polling errors retain the `PollFailed` mapping. Every event, Policy, Store, and cleanup outcome is deliberately silent before Module 10: no temporary warning, rate limiter, log-ring event, counter, metric, status, or operator-facing state is added. Tests observe failures through fakes and state assertions; Module 10 owns future diagnostics, while `DF-8` owns any Observability Surface. |
| 8E-11 | Cutover sequence and legacy deletion inventory | Resolved: the correlated path may be developed incrementally behind standalone test harnesses, but production performs one atomic switch only after those gates pass. The same 8E slice selects the new XDP/TC ABI, wires storage binding/consumer/Store cleanup, and performs strict semantic deletion. Delete the old C cache/parser/bridge sources and obsolete `types.h`/`xdp_parser.h`; move the few live constants to narrow owners and delete `constants.h`; replace the contents of `cache.bpf.c`; delete tests that only verify the old hash/parser/cache/arena-slot Contract, the old DNS microbenchmark, the c-ares expansion test and dependency; remove the `ecs`/`SHINKU_ECS_ENABLED` build plumbing while retaining ECS Pass-through vectors; and remove `ebpf.arena_pages` from Config through Session because layout derives it. Existing tests, benchmark code/results, and current documentation have no preservation entitlement: retain and rewrite only concrete parts useful to the new MVP, and delete everything else. Historical ADRs and dated audits remain history, while Git is the only archive for deleted implementation. No runtime selector, Meson option, compile-time fallback, shadow path, dual-write, dormant source archive, or Module 11 cleanup deferral is allowed; Git revert is rollback. |
| 8E-12 | End-to-end acceptance and synchronous Fill | Resolved for MVP: this is a rewrite against the new Contract, so legacy behavior, tests, benchmarks, and results are not acceptance baselines. Contract-complete layered correctness evidence remains required, with every behavior mapped to deterministic proof and every critical cross-layer workflow proven end to end. Decision 41 requires all tests to pass on the current development host. `PERF-M8-1` records reproducible new-system evidence without a product pass line. Synchronous callback-local Fill is fixed for Module 8: low QPS, limited Fill throughput, low Hit ratio, or ring-pressure Fill loss establishes the baseline but does not trigger `FillWork`. Incorrect Responses, forwarding loss, stop failure, or failure of packet-ring polling to make sustained progress remain blocking Contract failures. Any asynchronous Fill design is a separate post-MVP decision. |
| 8E-13 | MVP test execution environment | Resolved: Module 8 designs no CI matrix. Every current-Contract test must pass on the current development host, including unprivileged tests, BPF build, privileged verifier/program tests, root namespace integration, lifecycle coverage, soak, and fuzz smoke. Required privileges or dependencies must be supplied locally; a privilege skip is not a passing completion result. Record the host kernel, toolchain, commands, and results. `PERF-M8-1` remains separate required performance evidence. |

### 8E design review gate

The 2026-08-02 design review found three implementation blockers and four important follow-ups. All seven findings and all 8E-1 through 8E-13 decision points are resolved for the MVP. These findings are recorded in [Module 8E Design Review Findings](../decisions/module-08e-design-review-findings.md). The design-review and decision gates no longer block production implementation. The `PERF-M8-1` design is frozen, its harness is implemented, and privileged smoke passed; canonical evidence remains pending.

Verification:

- Run every Module 8 current-Contract test on the current MVP development host and record the kernel, toolchain, commands, and results; a privilege-dependent skip is not a passing result. CI design is outside Module 8.
- Layered DNS wire-parser, policy, and `classify_response()` facade tests, plus optional Clang libFuzzer targets whose minimized failures become committed regressions.
- Cache store tests.
- Shared fingerprint reference-vector and ABI tests required by the current Cache Key and Pending Query Contract.
- Focused tests proving that every Query with `ARCOUNT != 0`, including ECS-bearing Queries, passes through without a non-ECS Cache Hit or Cache Fill.
- Query-correlation tests proving that Bypass, unsolicited, expired, and mismatched Responses cannot create Cache Entries; a matching eligible Cache Miss can; and Pending Query exhaustion remains Fail-open.
- Query-correlation tests proving that Question mismatch does not consume a still-live Pending Query, while the first complete match does and a duplicate Response cannot trigger another Cache Fill.
- Query Eligibility vector tests proving that every Backend applies the same DNS-level profile while retaining Backend-specific packet-envelope coverage.
- Pending HASH cleanup tests covering timeout boundaries, bounded cursor continuation, refresh-before-recheck, the accepted refresh-after-recheck lost-Fill race, immutable Claimed deletion, delete failure, map exhaustion, and prompt stop between batches.
- A benchmark matrix comparing a reference DNS service with and without its native cache against the same service with Shinku, including the combined-cache case. Report single-node throughput, p99 latency, and DNS-service CPU use for the same hot `A/IN` workload.
- eBPF Backend remains runnable throughout the cutover.

Performance choices and deferred alternatives are tracked in [Refactor Benchmark Backlog](../benchmark-backlog.md). Product capabilities intentionally postponed beyond their current module are tracked in [Deferred Feature Backlog](../deferred-features.md).

### 8E implementation result

Implementation date: 2026-08-03

The production cutover is implemented. The daemon now ships one correlated eBPF Cache Contract: XDP performs complete Query Eligibility, Cache Hit replay, and Pending admission; TC performs exact reverse-tuple correlation, reserve/copy-before-CAS claim, and fixed-event publication; the Host Runtime synchronously decodes, classifies, and stores each active Response prefix. The Backend owns the typed consumer, DNS Policy, Store, bounded Pending cleaner, packet-ring quantum, and independent cleanup worker cadences with borrower-before-owner shutdown.

The strict 8E-11 deletion was applied in the same cutover. The legacy C cache/parser/hash/bridge implementation, its C ABI headers, c-ares dependency, ECS build selector, `ebpf.arena_pages`, legacy-only tests, and old DNS microbenchmark were removed. ECS-bearing and other Additional-Section Queries remain explicit Pass-through coverage rather than a dormant ECS-aware implementation.

Correctness evidence on the MVP development host:

- Host: Fedora kernel `7.1.5-201.fc44.x86_64`, Clang `22.1.8`, Meson `1.11.2`, bpftool `7.6.0`, libbpf `1.6.3`.
- `meson compile -C build`: passed, including the production BPF object and daemon.
- `sudo env ASAN_OPTIONS=detect_leaks=0 meson test -C build --print-errorlogs`: 14 passed, 0 failed, 0 skipped.
- Direct privileged `ebpf_cache_verifier_test` and `ebpf_production_verifier_test`: both passed. The production gate loads the real XDP/TC programs and proves Pending create/refresh/claim/tombstone behavior, duplicate suppression, event framing, Cache Hit rewriting, Transaction ID and Question rebinding, TTL aging, checksum normalization, and expired-publication miss admission.
- `sudo env ASAN_OPTIONS=detect_leaks=0 python3 tests/integration/test_dns_cache.py -v`: 22 passed. The namespace suite covers startup, XDP/TC attach, miss-to-Fill-to-Hit, positive/negative/CNAME replay, TTL expiry, ECS Pass-through, unsupported Query/Response Pass-through, ping forwarding, signal shutdown, detach, and invalid-interface failure.
- Separate Clang fuzz build with `-Ddns_fuzzing=true`: both parser and policy targets passed 1,000-run ASan/UBSan smoke tests from their committed corpora.
- `SOAK_DURATION_SEC=30 SAMPLE_INTERVAL_SEC=5 tests/soak/run_soak_with_unbound_docker.sh`: 16/16 successful Queries, 0 timeouts, 0 nonzero RCODEs, and 0 anomalies; Docker, namespace, daemon, and hook cleanup completed.
- `git diff --check` and Python bytecode compilation for the integration harness passed.

`meson compile -C build tidy` was executed and remains nonzero because the current translation-unit set reports include-cleaner findings, existing Config/ProcessControl findings, and one generated-skeleton analyzer warning. No correctness test is skipped because of that result. The frozen `PERF-M8-1` harness and privileged smoke are complete, but canonical performance evidence remains required before Module 8 closes. No product pass line is introduced by 8E.
