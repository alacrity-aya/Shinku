# Module 8E Design Review Findings

## Review status

Review date: 2026-08-02

Implementation status: production cutover correctness completed on 2026-08-03. The verifier, Host unit, root namespace, fuzz-smoke, and short Docker-soak evidence is recorded in the Module 8 implementation result. Canonical `PERF-M8-1` remains a deferred TODO for final Module 8 performance closure; it does not block the active Module 9 work.

This review checked the Module 8E decision set against the Module 8B/8C/8D contracts, the current eBPF Session/Backend boundaries, libbpf ring-buffer behavior, and the verifier feasibility code. It is a design gate, not an implementation approval. The benchmark backlog is intentionally frozen; performance-specific questions remain deferred unless they affect one of the findings below.

The overall composition is coherent: Query Eligibility before lookup, one shared Query parse, tuple-plus-Transaction-ID correlation with a keyed fingerprint, reserve/copy before CAS, a typed synchronous Host callback, explicit resource ordering, and a staged build followed by one atomic production cutover are all reasonable foundations.

## Blocking findings

### 8E-R1 — Pending Query lifecycle and reclamation

Status: Resolved for MVP. The accepted design favors a simpler bounded HASH cleaner and explicitly records its narrow Fail-open race rather than claiming strict atomic cleanup.

Evidence:

- The production representation is fixed as bounded HASH with Host cleanup. Ownership, cadence, map borrowing, batch/cursor behavior, and shutdown are resolved.
- The accepted ownership extends the single Backend `CleanupWorker` to borrow independent `CacheStore` and `PendingQueryCleaner` collaborators. It maintains independent deadlines and fair bounded dispatch; Session cleanup remains rejected.
- Strict atomic reclamation was reconsidered and rejected as disproportionate. The accepted cleaner performs bounded snapshot lookup plus an immediate recheck before delete. A refresh in the final recheck/delete window may lose one Fill, but cannot authorize a mismatched Response, mutate an existing Cache Entry, or affect forwarding.
- `Claimed` post-submit behavior was initially undefined. The accepted resolution now retains it as a consumed-exchange tombstone until Pending Query Timeout cleanup; XDP cannot refresh, overwrite, or reactivate it, TC cannot authorize another Fill from it, and the Response path never deletes it after submit.
- LRU can evict a Claimed tombstone before timeout and permit same-key recreation followed by a duplicate old Response. It is therefore rejected for the MVP rather than retained as a performance-only candidate.

Implementation evidence:

- Each Pending batch inspects at most 256 snapshots with `bpf_map_lookup_batch()` and a persistent opaque cursor. Terminal or error completion resets the sweep. The worker checks stop and alternates due Cache/Pending work between batches. Pending normal cadence is `pending_query_timeout / 2`, independently of Cache `cleanup_interval`.
- Implement deterministic HASH cleanup tests for refresh before recheck, the accepted refresh after recheck lost-Fill race, immutable Claimed deletion, delete failure, map exhaustion, cursor continuation, and prompt stop between batches.
- Reopen HASH versus LRU or the 256-record quantum only with production-shaped evidence of material correlation loss, persistent incomplete sweeps, cleanup CPU harm, or unacceptable stop/Cache-cleanup delay. Reopening LRU also requires an explicit decision about early tombstone eviction and duplicate Fill.

Grill result: decisions 28 through 32 close this finding for MVP.

### 8E-R2 — Response arrival time is missing from the Fill contract

Severity: High. Blocks the current fixed event ABI and the TTL freshness proof.

Status: Resolved for MVP. Decisions 33 through 35 make TC Response Observation Time authoritative, define observation-based expiry plus admission-time rejection and victim liveness, and prevent an older or equal same-key observation from replacing a newer published entry.

The previous fixed event carried no timestamp, while Host composition read `CLOCK_BOOTTIME` immediately before `CacheStore::store()`. That would have computed `stored_at + lifetime` from callback time, allowing ring delay to extend DNS TTL. The accepted event now preserves observation time, but the current Store interface still accepts only one `now` value and must be revised coherently.

Required resolution before coding:

- TTL residence starts at TC observation. The 528-byte event carries native-endian 64-bit `response_observed_at_ns`, captured after complete validation and before reserve; Host callback time cannot replace it.
- `CacheCandidate` remains unchanged. Store receives `(candidate, observed_at, now)`, trusts the TC/decoder/Policy chain for representable ordered BOOTTIME and complete bounded Candidate data, rejects only candidates exhausted before admission, persists observation-based `stored_at` and expiry, lets XDP age every RR from that timestamp, and evaluates victim expiry at admission `now`.
- Same-key Store Admission requires `incoming observed_at > existing stored_at`; older or equal observations return normal `Rejected` without mutation, even when the existing entry is expired or the incoming expiry is later.
- Add a ring-delay/short-TTL boundary test, including delay beyond the complete DNS lifetime.

Grill result: decisions 33 through 35 close this finding for MVP. Tests cover ring delay below/equal/above lifetime, per-RR TTL aging, victim liveness at admission, and older/equal/newer same-key ordering. Tests do not manufacture future, negative, overflowed, or structurally incomplete internal values.

### 8E-R3 — Packet-ring polling work quantum

Status: Resolved for MVP. Decision 36 bounds one Backend poll to 64 synchronous packet callbacks and returns control to Runner before consuming further backlog.

The previous Session used unbounded `ring_buffer__poll()`. The accepted Session first calls `ring_buffer__consume_n(..., 64)` without blocking; if empty, it waits on the packet-ring epoll fd up to the configured timeout and then performs one more bounded consume. Empty, partial, and full batches complete the quantum successfully, the callback remains always-zero, and Runner checks Stop Condition before the next Backend poll. ADR-0047 removes the former activity result.

Implementation evidence:

- Test ready backlog without wait, timeout, readiness followed by consume, exactly 64 events with sustained producers, interruption and real errors in both wait and consume, Stop Request after a full batch, and cleanup-worker shutdown while callbacks are active.
- Reopen the fixed quantum only if production-shaped evidence shows unacceptable throughput, callback latency, or stop latency; do not add runtime configuration without that evidence.

Grill result: decision 36 closes this finding for MVP.

## Important but non-blocking findings

### 8E-R4 — Fixed event inactive-tail boundary

Status: Resolved for MVP. Decision 37 explicitly treats the inactive suffix as unspecified bytes visible in the raw callback span but outside semantic event data.

The sole Backend decoder may interpret and propagate only the validated header and active Response prefix. It cannot read, compare, copy, hash, serialize, log, diagnose, or pass the tail to Policy or Store. Poisoned-tail tests prove semantic independence and raw-boundary visibility. `PERF-8E-2` accounts for the 528-byte reservation without a clearing pass. Raw event export or cross-process delivery must reopen this boundary first.

### 8E-R5 — XDP post-resize mutation contract

Status: Resolved for MVP. Decision 38 requires complete output construction in per-CPU scratch and makes `bpf_xdp_adjust_tail()` the packet-mutation commit boundary. Pre-adjust and adjust failure return `XDP_PASS`; after adjust success, bounds or the single complete-frame store failure returns `XDP_DROP`, and success returns `XDP_TX`. No post-adjust path may return `XDP_PASS`, and rollback/incremental mutation are forbidden. Verifier and program tests must cover maximum/variable lengths and every commit outcome.

### 8E-R6 — Pending configuration and native binding

Status: Resolved for MVP. Decision 39 introduces checked `EbpfSkeletonConfig` with cache layout, secret, Pending capacity, and nanosecond timeout, and one `prepare_skeleton(config)` call returning a move-only composite non-owning binding. Store receives only the cache-map/arena loan; Cleaner receives only the Pending-map loan. Session remains sole native owner and carries no cleanup policy. Tests must verify pre-load map/rodata configuration, checked conversion, one-time loan splitting, partial failure unwind, and borrower-before-owner destruction.

### 8E-R7 — Canonical module documentation still contains superseded requirements

Status: Resolved for MVP. ADR-0003 remains historical but now prominently qualifies its old "existing eBPF tests" requirement through the current Module 8E Contract. Operational Loops and a runnable Backend remain mandatory; individual legacy implementations, tests, benchmarks, and results have no preservation entitlement.

The Module 8 page now requires Contract-complete layered evidence rather than equivalent legacy coverage, labels the decision queue by current status, removes obsolete generic DNS parser/hash test requirements, and links the current production-cutover decisions. Rewriting ADR-0003's historical rationale or leaving its conflict implicit were rejected.

Grill result: decision 40 closes this finding for MVP.

## Review gate and grilling order

Findings 8E-R1 through 8E-R7 and decision points 8E-1 through 8E-13 are closed for the MVP. Decision 41 requires all Module 8 current-Contract tests to pass on the current development host and places CI design outside the MVP. Decision 42 fixes synchronous callback-local Fill without an asynchronous performance trigger. The design-review and decision gates no longer pause production implementation.

The next grill should ask exactly one question at a time in this order:

No unresolved Module 8E grill question remains. Implementation evidence may reopen a specific decision only under its recorded trigger; the canonical benchmark remains explicitly deferred rather than silently dropped.
