# Shinku Roadmap (Code-Truth Aligned)

This roadmap is based on the current repository state, not historical assumptions.

## 0. Current State Snapshot (What is already done)

### Already implemented
- XDP hot path cache serve with `XDP_TX` and arena-backed payload copy (`src/bpf/cache.bpf.c`).
- Userspace ingest path with DNS validation + name flattening + cache insertion (`src/core/dns_parser.c`).
- Ring allocator semantics for arena slot selection (`next_idx` atomic increment with modulo), not bump-only allocation.
- Concurrency safety for shared arena entries:
  - seqlock (`cache_entry.seq`)
  - generation check (`cache_entry.gen` vs `cache_value.gen`)
  - stale slot owner eviction (`slot_owners`).
- TTL expiry cleanup loop in userspace via background cleanup thread (`start_cleanup_thread`, `cleanup_expired_entries`).
- CNAME ingest support in parser answer loop (with terminal A/AAAA requirement for A/AAAA queries).
- **Negative caching (P1.1 complete)**:
  - NXDOMAIN/NODATA caching with SOA-derived TTL policy (`parse_negative_cache_info`).
  - TTL bounds: `NEGATIVE_TTL_MIN` (5s) and `NEGATIVE_TTL_MAX` (600s) per RFC 2308.
  - Separate flags: `CACHE_VALUE_FLAG_NEGATIVE` and `CACHE_VALUE_FLAG_NXDOMAIN`.
  - Metrics: `shinku_negative_accept_total{type=nxdomain|nodata}`, `shinku_negative_reject_total`.
- Unit tests for parser, cache correctness, arena list/hash table, hash consistency, integration smoke tests.
- **Observability baseline (P0.1 complete)**:
  - Prometheus `/metrics` endpoint with sampled BPF counters and userspace counters.
  - `/healthz` and `/readyz` endpoints for health/readiness probes.
  - Configurable sampling via `--obs-bpf-mask` and toggle via `--obs` / `--obs-bpf`.
  - Performance-safe: BPF counters use percpu map with sampling; userspace counters use relaxed atomics.
  - Test coverage: `tests/unit/obs/obs_http_test.c`.
- **Failure-mode policy baseline (P0.2 complete)**:
  - Bounded retry + exponential backoff in startup attach paths (XDP/TC) to prevent crash-loop behavior.
  - Explicit degraded-mode state machine in userspace with reason flags:
    - `userspace_lag`
    - `cleanup_failure`
    - `startup_attach_retry`
    - `cache_map_update_failure`
  - Deterministic degradation activation based on streak thresholds (lag/cleanup/cache_map update failures).
  - Degraded mode exported via `/metrics`:
    - `shinku_degraded_mode`
    - `shinku_degraded_reason_active{reason=...}`
    - `shinku_degraded_transitions_total`
    - `shinku_degraded_reason_set_total{reason=...}`
  - Performance-first implementation:
    - no locking in hot path (relaxed atomics only)
    - bounded integer threshold checks
    - no extra allocations in fast path.
  - Test coverage: `tests/unit/degraded/degraded_mode_test.c`.

### Partially implemented
- ECS handling is now subnet-partitioned for IPv4 ECS keys (`ecs_addr_v4`, `ecs_prefix`, `ecs_family`) to prevent cross-subnet cache pollution.
- CNAME support is ingest-level acceptance; no advanced chain policy controls (loop-depth policy, richer negative interactions).
- TCX attach fallback exists (legacy TC), but no staged rollout/health-gated deployment flow.

### Not yet implemented
- IPv6 fast path (XDP ingress/egress mutation for IPv6) — **deferred, low priority**.
- DNS-over-TCP capture/cache strategy.
- CI/CD pipeline and release automation (no `.github/workflows`).

---

## 1. Industrialization Gap Analysis

To be “industrial-grade,” Shinku must close six categories of gaps:

1. **Protocol coverage and correctness boundaries**
2. **Cache lifecycle and capacity governance**
3. **Observability and operability**
4. **Production deployment and upgrade safety**
5. **Failure-mode handling and security posture**
6. **Testing matrix and release engineering**

This plan prioritizes reliability and operability before feature breadth.

### 1.1 Real-network reasonability gaps (non-IPv6)

From a real production DNS perspective, the highest remaining “unreasonable” points are:

1. **Single-upstream dependency without health-based failover policy**
   - Current behavior assumes a single healthy upstream path; attach/degraded handling exists, but upstream pool health/routing policy is not defined.
2. **No explicit truncation/TCP fallback strategy**
   - Parser currently rejects TC responses; this is fine for strict UDP cacheability but incomplete for mixed real traffic where truncation is normal.
3. **EDNS behavior is not fully operationalized**
   - ECS baseline exists, but end-to-end policy for EDNS fallback/normalization (including malformed or unsupported EDNS behaviors) is not fully specified.
4. **Capacity governance is too coarse under churn**
   - Ring-slot overwrite is efficient, but lacks policy-level admission/eviction controls for hot-key preservation and high-cardinality pressure.
5. **No stale-serve policy during upstream instability**
   - Current TTL expiry is strict; in real outages, controlled stale serve (`stale-if-error`) is often preferable to hard miss.
6. **Security hardening remains too abstract**
   - Rate limiting, ACL/source policy, and anti-amplification posture are listed but not planned as concrete deliverables.
7. **SLO-first operations are still incomplete**
   - Metrics exist, but SLO targets, alert thresholds, and runbook-driven remediation paths are not yet encoded.

These are prioritized below in P0/P1/P2 without introducing IPv6 scope.

---

## 2. Prioritized Implementation Plan

## P0 (Must-have before production rollout)

### P0.1 Observability baseline (metrics + health)
**Goal:** Make behavior measurable and debuggable in production.

**Implement**
- Add userspace metrics endpoint (Prometheus text format) with at least:
  - `shinku_cache_hit_total`
  - `shinku_cache_miss_total`
  - `shinku_cache_expired_hit_total`
  - `shinku_cache_insert_total`
  - `shinku_cache_insert_fail_total`
  - `shinku_cache_cleanup_removed_total`
  - `shinku_parser_reject_total{reason=...}`
  - `shinku_rb_pkt_drop_total`
  - `shinku_xdp_tx_total`
- Add `/healthz` (process live) and `/readyz` (BPF programs attached + rings initialized).
- Preserve low overhead: use per-thread/per-CPU counters where feasible and batch export in userspace.

**Acceptance criteria**
- Metrics exposed locally and scrapeable.
- On synthetic failures, counters move predictably.
- No measurable regression >3% QPS in benchmark mode with metrics enabled.

---

### P0.2 Failure-mode policy and graceful degradation ✅
**Goal:** Fail safe, not fail opaque.

**Implement**
- Define and encode explicit behavior for:
  - userspace lag/ring backlog growth
  - cleanup thread failure
  - attach/reattach failure at startup
  - cache_map update failures
- Add bounded retry + backoff for startup attach paths.
- Add explicit “degraded mode” state in userspace logs/metrics.

**Acceptance criteria**
- Fault injection scenarios produce deterministic fallback behavior.
- No crash loops under repeated attach failures.

**Status:** Implemented in baseline form with startup retry/backoff + degraded state metrics + deterministic threshold policy.

---

### P0.3 IPv6 support (end-to-end) ⏸️ DEFERRED
**Goal:** Remove major protocol coverage gap for dual-stack deployments.

**Status:** Deferred to lower priority. IPv6 fast path is not currently a target for this project. Revisit if dual-stack deployments become a requirement.

**Implement** (when resumed):
- XDP ingress parse for `ETH_P_IPV6`, extension-header policy, UDP DNS query extraction.
- Cache hit response rewrite for IPv6 headers and mandatory UDP checksum handling.
- TC egress capture path for IPv6 UDP/53 responses.
- Userspace parser acceptance for IPv6-sourced packets (payload logic remains mostly shared).

**Acceptance criteria**
- Integration tests for AAAA queries over IPv6 path.
- No checksum errors observed in packet captures.

---

### P0.4 Soak and operational readiness package
**Goal:** Validate long-run stability and provide deployable runbook.

**Implement**
- 24h and 72h soak tests with mixed query distributions.
- Capacity and churn tests (high eviction pressure, TTL churn, domain cardinality spikes).
- Operational docs:
  - deployment checklist
  - rollback checklist
  - incident triage quick-guide

**Acceptance criteria**
- No unbounded memory growth in userspace.
- Stable cache hit rate envelope under repeated churn.

---

### P0.5 Transport and fallback correctness (UDP truncation/TCP strategy)
**Goal:** Make behavior sane under real DNS response size/path constraints.

**Implement**
- Define explicit policy for `TC=1` responses:
  - pass-through only,
  - optional userspace TCP retry module (future),
  - observability tags for truncation-triggered misses.
- Add integration scenarios for large/TC responses and verify deterministic behavior.

**Acceptance criteria**
- No ambiguous handling of truncated responses.
- Metrics expose truncation-driven bypass/miss volume.

---

### P0.6 Upstream resiliency baseline
**Goal:** Avoid single-upstream fragility in real networks.

**Implement**
- Introduce upstream pool health checks (at least primary + backup policy).
- Add bounded failover/failback policy with jittered probes.
- Expose upstream health/failover counters in metrics.

**Acceptance criteria**
- Fault injection on primary upstream does not cause prolonged resolution failure.
- Automatic recovery to primary is bounded and observable.

---

### P0.7 Resolver security baseline (cache poisoning resistance)
**Goal:** Raise spoofing/poisoning cost to production-grade baseline.

**Implement**
- Add strict response correlation policy in userspace ingest (5-tuple + DNS ID + question tuple consistency checks where applicable).
- Add query coalescing for identical in-flight upstream lookups.
- Define and implement entropy requirements for upstream query source port and transaction ID handling policy.

**Acceptance criteria**
- Documented threat model + mitigation checklist in docs.
- Integration/fault-injection tests validate rejection of mismatched/spoof-like response shapes.

---

## P1 (High-value improvements immediately after P0)

### P1.1 Negative caching ✅
**Goal:** Cut upstream load and latency for repeated negative lookups.

**Status:** Implemented. NXDOMAIN/NODATA caching with SOA-derived TTL policy, bounded by `NEGATIVE_TTL_MIN`/`NEGATIVE_TTL_MAX`.

**Implement**
- Cache NXDOMAIN/NODATA with SOA-based TTL bounds.
- Separate key semantics for negative entries where needed.
- Add parser rejection/acceptance metrics per negative type.

**Acceptance criteria**
- Unit + integration tests for NXDOMAIN/NODATA.
- TTL expiry behavior matches policy.

---

### P1.2 CNAME hardening and integration coverage ✅
**Goal:** Move from basic support to robust production semantics.

**Implement**
- Add integration tests with mock server returning:
  - CNAME + A
  - CNAME chain + terminal A/AAAA
  - CNAME-only for A/AAAA query (must reject cache insert)
- Add parser reasons metrics for CNAME reject categories.
- Optional policy knobs: max accepted chain depth, stricter owner/target linkage checks.

**Acceptance criteria**
- Integration suite validates cache-hit behavior for CNAME-backed answers.
- No regressions in existing parser/cache tests.

**Status:** Implemented for current policy scope:
- CNAME + terminal A and CNAME chain + terminal A cache-hit integration tests.
- CNAME-only and AAAA-only-terminal rejection paths tested and exposed in parser reject metrics.

---

### P1.3 Hitless update path
**Goal:** Reduce disruption during binary/program upgrades.

**Implement**
- Introduce controlled upgrade flow for BPF programs (link update strategy).
- Add pre-flight checks and rollback on failed update.

**Acceptance criteria**
- Upgrade test shows no sustained DNS outage window.

---

### P1.4 Native XDP validation on physical NIC
**Goal:** Prove production performance envelope beyond veth/generic mode.

**Implement**
- Benchmark matrix on at least one native-XDP-capable NIC.
- Compare SKB/generic vs native mode with same workload.

**Acceptance criteria**
- Publish reproducible report with hardware/kernel details and confidence intervals.

---

### P1.5 Upstream cache warm-refresh
**Goal:** Maintain upstream DNS server cache efficiency by proactively refreshing before/at expiry.

**Rationale:** When local cache entries expire, upstream DNS servers may also have evicted their cached responses. Proactively querying upstream before or at local expiry helps maintain warm caches upstream, reducing overall DNS latency for dependent queries.

**Implement**
- Track entries approaching TTL expiry (e.g., at 80-90% of TTL).
- Optionally issue proactive DNS queries to upstream for soon-to-expire entries.
- Refresh local cache with new response, resetting TTL.
- Policy knobs:
  - `--refresh-before-expiry` (enable/disable proactive refresh)
  - `--refresh-threshold` (percentage of TTL before refresh, default 90%)
  - `--refresh-jitter` (randomize refresh timing to avoid thundering herd)

**Acceptance criteria**
- Configurable refresh policy.
- Upstream cache hit rate improves under repeated query patterns.
- No significant additional upstream load under normal operation.

---

### P1.6 EDNS behavior hardening
**Goal:** Make EDNS/ECS behavior predictable across heterogeneous resolvers.

**Implement**
- Document and enforce EDNS normalization policy for cache keying.
- Add explicit malformed/unsupported EDNS fallback behavior (pass-through vs reject) with reason metrics.
- Add integration tests for mixed OPT options, unknown options, and malformed-length cases.

**Acceptance criteria**
- ECS anti-pollution guarantees remain intact under mixed EDNS option sets.
- EDNS parse failures are observable and do not destabilize cache behavior.

---

### P1.7 SLO + runbook operationalization
**Goal:** Convert existing metrics into actionable operations.

**Implement**
- Define SLOs for hit ratio, miss ratio, parser reject ratio, and degraded mode duration.
- Add alert thresholds and runbook mapping per degraded reason.
- Add benchmark-to-SLO interpretation section in docs/performance.

**Acceptance criteria**
- Oncall can detect and triage degraded states using documented thresholds.
- SLO compliance can be evaluated directly from exported metrics.

---

### P1.8 Truncation/TCP operational path
**Goal:** Handle large-answer realities without ambiguous behavior.

**Implement**
- Add explicit TCP retry path policy for truncated answers (initially userspace path acceptable).
- Add metrics for truncation ratio, TCP retry success/failure, and fallback latency impact.

**Acceptance criteria**
- TC-heavy integration scenarios have deterministic behavior and observability.
- No silent drops or indefinite retry loops.

---

## P2 (Strategic scope expansion)

### P2.1 ECS hardening follow-ups
**Goal:** Extend ECS safety from current IPv4 partitioning baseline to broader production policies.

Current baseline already implemented:
- ECS-aware key partitioning to avoid cross-subnet reuse.
- ECS integration tests for same-subnet hit, different-subnet miss, and `/0` global behavior.

Remaining follow-ups:
- Scope-aware key normalization policy (RFC 7871 §7.3.1 aligned) with explicit mode switch:
  - `strict-source` (current behavior, exact source-prefix partition)
  - `scope-aware` (normalize cache key by validated scope prefix when safe)
  - optional guarded hybrid mode for controlled aggregation
- Add validation guardrails for normalization:
  - only allow normalization when `scope <= source`
  - preserve anti-pollution invariants in cross-subnet integration tests
  - cap normalization breadth via configurable prefix floor to avoid cache blow-up
- Configurable ECS forwarding/normalization policy (`/24` defaults, privacy knobs).
- No-ECS-support zone memory/aggregation policy (future security hardening).
- Future IPv6 ECS support only if IPv6 scope is revisited.

### P2.1.1 ECS feature-gating and deployment profiles
**Goal:** Make ECS optional by build/deploy profile instead of mandatory behavior.

Plan:
- Introduce compile-time flag `SHINKU_ECS_ENABLED` (userspace + BPF) with Meson option wiring.
- Provide two first-class build profiles:
  - `ecs=disabled` (default): strict non-ECS cache key path (lean default for private/internal recursive deployments)
  - `ecs=enabled`: ECS parse + partition + normalization policy path (CDN/geo-sensitive deployments)

Performance invariant:
- ECS disabled profile must compile out ECS parse/key code paths with no runtime branches in hot path.

Acceptance criteria:
- `ecs=disabled` build has no ECS parsing in hot path and passes full test suite (except ECS-specific tests skipped by profile).
- `ecs=enabled` build preserves current ECS safety tests plus normalization-mode tests.

### P2.2 EDNS and large-response strategy
**Goal:** Improve behavior for >512-byte realities while preserving XDP hot-path safety.

### P2.3 DNS-over-TCP handling strategy
**Goal:** Define and implement coherent policy for truncated/large-answer flows.

### P2.4 Advanced admission/eviction policy
**Goal:** Improve hit ratio under skew/churn (e.g., admission filtering, smarter eviction).

### P2.6 Stale-if-error / stale-while-revalidate policy
**Goal:** Improve availability and tail-latency during upstream instability.

### P2.7 Security execution package (non-IPv6)
**Goal:** Convert security hardening from generic intent to concrete controls.

Planned controls:
- per-client/per-subnet QPS limits,
- optional source ACL mode,
- anti-amplification safeguards for suspicious query patterns,
- auditable deny/reject metrics.

### P2.8 Attack-surface expansion gate (deployment-driven)
**Goal:** Expand to water-torture / amplification defense only when deployment role requires it.

Prioritization policy:
- Recursive/forwarder in controlled networks:
  - keep focus on cache correctness, upstream resiliency, and abuse observability first.
  - treat heavy anti-DDoS features as optional add-ons.
- Authoritative-facing or Internet-exposed resolver role:
  - prioritize water-torture controls (random-subdomain miss shaping, negative-response strategy tuning, upstream protection).
  - prioritize amplification controls (open-resolver exposure prevention, response shaping/limiting, ACL defaults).

Acceptance criteria:
- A deployment-role matrix is documented (default profile vs exposed profile).
- Security controls are mapped to role-specific SLO/alert thresholds and benchmark scenarios.

### P2.5 Security hardening
**Goal:** Minimize abuse/risk surface (ACLs, anti-reflection posture, least-privilege runtime).

---

## 3. Engineering Program Plan (12-week concrete schedule)

### Weeks 1-2: Observability foundation
- Implement metrics schema and exporter.
- Add health/readiness endpoints.
- Add parser reject reason taxonomy.

### Weeks 3-4: Failure-mode hardening
- Add degraded mode logic and retries/backoff.
- Add startup/attach failure scenarios in tests.

### Weeks 5-7: CNAME integration + Cache lifecycle
- Expand integration mock server scenarios for CNAME chains.
- Implement upstream cache warm-refresh (proactive TTL refresh).
- Add refresh policy configuration knobs.

### Weeks 8-9: Soak testing and validation
- Execute 24h/72h soak and churn scenarios.
- Validate cache refresh behavior under load.

### Weeks 10-11: Native XDP + soak campaign
- Run native NIC benchmarks.
- Execute 24h/72h soak and churn scenarios.

### Week 12: Release packaging
- Deployment/rollback runbooks.
- Versioned release notes and compatibility matrix.

---

## 4. Definition of “Industrial-Ready v1”

Shinku reaches industrial-ready v1 when all are true:

- P0 items complete and verified (IPv6 deferred).
- SLO instrumentation exists with alertable metrics.
- IPv4 fast path validated.
- Negative caching operational with TTL policy ✅.
- CNAME integration tests passing in CI + root integration environment.
- Soak tests pass with no critical leaks/crashes.
- Documented rollout and rollback procedures available.

---

## 5. Notes on corrected historical assumptions

- Arena allocation is **not** a pure bump allocator anymore; it is ring-style index progression with slot reuse handling.
- TTL cleanup is **implemented** via background thread and periodic `cleanup_expired_entries`.
- CNAME ingest support is **implemented** with terminal RR gating for A/AAAA query correctness.
- Negative caching is **implemented** with SOA-derived TTL policy and bounded TTL limits.
- Remaining work focuses on production operations maturity, broader protocol coverage, and release engineering.
