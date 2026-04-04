# Shinku Roadmap (Sidecar / Co-located Mode, Code-Truth Aligned)

This roadmap is aligned with the current codebase and intended deployment mode:

- **Shinku is a kernel-level DNS cache proxy/sidecar**, co-located with an upstream resolver on the same node (physical or VM).
- Primary value is **latency shielding + upstream load reduction** on hot/miss-prone traffic, not multi-upstream recursive orchestration.

---

## 0. Current State Snapshot (Implemented vs Pending)

### Architectural Scope Note

Shinku is a **transparent XDP-layer DNS cache**, not a recursive resolver. It intercepts cache hits at the kernel level and passes cache misses through to the existing DNS infrastructure via `XDP_PASS`. Upstream DNS high availability (pool management, health checks, failover) is the responsibility of the upstream resolver (e.g., CoreDNS, Unbound, BIND) and is explicitly out of scope for this project. Shinku's failure mode is **fail-open**: if the daemon crashes or BPF programs detach, all traffic falls through to the upstream resolver without interruption.

To be "industrial-grade," Shinku must close six categories of gaps:

1. **XDP/TC cache pipeline (IPv4 path)**
   - XDP serves hits via `XDP_TX`, miss passes through upstream path.
   - TC captures upstream responses and userspace writes cache entries.

2. **Parser + cache correctness baseline**
   - DNS answer parse + flatten + store path implemented.
   - CNAME acceptance with terminal RR guardrails (for current policy scope).
   - Negative caching (NXDOMAIN/NODATA + SOA-based bounded TTL).

3. **Cache lifecycle + safety**
   - Ring-slot allocation, seq/generation consistency, owner tracking.
   - Background cleanup thread for TTL-expired entry removal.

4. **Admission/eviction system (implemented, modularized)**
   - Minimum TTL gating, recent-insert dampening, pressure-mode rejection.
   - Count-Min sketch + hot/cold segmentation.
   - Code split: `cache_sketch.c`, `cache_recent.c`, `cache_segments.c`.

5. **Observability + degraded-mode baseline**
   - `/metrics`, `/healthz`, `/readyz` exported.
   - Degraded reason/state machine + counters/gauges implemented.
   - Truncation ratio and fallback efficacy metrics exposed (P0.5 closeout).
   - Grafana dashboard panels and Prometheus alert rules for P0.5 metrics.

6. **Transport fallback baseline**
   - `TC=1` UDP responses are cacheable fallback hints with integration coverage.
   - Deterministic UDP TC=1 behavior and client TCP-retry expectation documented.

7. **Privilege model baseline (least privilege startup)**
   - Privilege check occurs **after CLI parsing**.
   - Startup allowed as root or via file capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`).

From a real production DNS perspective, the highest remaining "unreasonable" points are:

1. ~~**No explicit truncation/TCP fallback strategy**~~ — **RESOLVED**: TC=1 cache fallback baseline + metrics + behavior docs complete.
2. **EDNS behavior is not fully operationalized**
   - ECS baseline exists, but end-to-end policy for EDNS fallback/normalization (including malformed or unsupported EDNS behaviors) is not fully specified.
3. **Capacity governance is too coarse under churn**
   - Ring-slot overwrite is efficient, but lacks policy-level admission/eviction controls for hot-key preservation and high-cardinality pressure.
4. **No stale-serve policy during upstream instability**
   - Current TTL expiry is strict; in real outages, controlled stale serve (`stale-if-error`) is often preferable to hard miss.
5. **Security hardening remains too abstract**
   - Rate limiting, ACL/source policy, and anti-amplification posture are listed but not planned as concrete deliverables.
6. **SLO-first operations are still incomplete**
   - Metrics exist, but SLO targets, alert thresholds, and runbook-driven remediation paths are not yet encoded.

### Deferred / Not targeted now

- IPv6 fast path (explicitly deferred).
- Full DNS-over-TCP capture/cache handling.
- CI/CD release automation pipeline.

---

## 1. Business Scenario Fit (Why priorities changed)

### Deployment model

Shinku is optimized for **co-located sidecar caching** in front of a local upstream resolver on the same node/network namespace test topology.

### Consequence on roadmap

- The previous **P0.6 "Upstream resiliency baseline" (multi-upstream failover/failback)** is **not a must-have** for this deployment mode and is removed from P0.
- For sidecar mode, higher-value work is:
  1) cache-hit consistency under churn,
  2) warm-refresh to keep both sidecar and local upstream cache hot,
  3) operational SLO/runbook maturity,
  4) security and abuse controls scoped to sidecar role.

---

## 2. Updated Priorities (Sidecar-first)

## P0 (Must-have before production rollout)

### P0.1 Observability baseline ✅
Already implemented. Keep extending only when new features require additional metrics.

### P0.2 Failure-mode policy and graceful degradation ✅
Already implemented baseline with retry/backoff + degraded reasons.

### P0.3 IPv6 support ⏸️ Deferred
No change.

### P0.4 Soak + operational readiness package
**Goal:** prove long-run stability in sidecar conditions.

**Implement next:**
- 24h/72h soak under mixed hot-key + long-tail + TTL churn traffic.
- Output runbook: deploy/rollback/incident checklist.

**Status:** Soak test infrastructure implemented (`tests/soak/` with Docker Unbound). 10min soak baseline passed.

### P0.5 Truncation/TCP operational completion ✅
**Current:**
- TC=1 cache fallback baseline exists.
- Truncation and fallback efficacy observability metrics are exposed.
- Deterministic UDP TC=1 behavior and client TCP-retry expectation are documented.
- Grafana dashboard panels and Prometheus alert rules added for truncation ratio and fallback efficacy.

**Status:** P0.5 closeout complete.

### P0.6 (Removed from P0): upstream pool failover/failback
Reason: not aligned with co-located sidecar model where upstream resolver is local and managed as node-local dependency.

If future product mode expands to standalone recursive resolver, revisit as separate roadmap branch.

### P0.7 ECS scope decision (current cycle)
ECS support is out of current roadmap scope. Planning and validation are done under non-ECS policy to keep behavior deterministic and operational complexity bounded.

### P0.8 Resolver security baseline (sidecar scope)
**Goal:** improve poisoning resistance and abuse safety without role creep.

**Implement next:**
- stronger response correlation checks,
- in-flight duplicate suppression (singleflight-style by key),
- sidecar-focused anti-amplification metrics/limits.

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
  - cache-and-serve truncated UDP responses as transport fallback hints,
  - clients retry over TCP to upstream (no local TCP synthesis yet),
  - optional userspace TCP retry module remains future work.
- Add integration scenarios for large/TC responses and verify deterministic behavior.

**Acceptance criteria**
- No ambiguous handling of truncated responses.
- Repeated UDP queries for the same large name avoid repeated upstream UDP pressure.

**Status:** Complete — cached `TC=1` UDP fallback behavior + integration coverage + truncation/fallback metrics + dashboard panels + alert rules.

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
Implemented.

### P1.2 CNAME hardening ✅ (current scope)
Implemented for current policy boundaries.

### P1.3 Hitless update path
Keep as high-value operational work item.

### P1.4 Native XDP validation on physical NIC
Keep for production confidence and perf envelope.

### P1.5 Upstream Cache Warm-Refresh (detailed plan below)
This is now the highest-value cache-lifecycle enhancement for sidecar mode.

### P1.6 EDNS behavior hardening
Keep.

### P1.7 SLO + runbook operationalization
Keep.

### P1.8 Truncation/TCP operational path
Keep (after P0.5 closure — now complete).

---

## P2 (Strategic expansion)

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

### P2.1.1 ECS feature-gating and deployment profiles ✅
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

Status: Meson feature gate + compile-time macro wiring implemented; integration tests are profile-gated.

### P2.2 EDNS and large-response strategy
**Goal:** Improve behavior for >512-byte realities while preserving XDP hot-path safety.

### P2.3 DNS-over-TCP handling strategy
**Goal:** Define and implement coherent policy for truncated/large-answer flows.

### P2.4 Advanced admission/eviction policy
**Goal:** Improve hit ratio under skew/churn (e.g., admission filtering, smarter eviction).

### P2.5 Stale-if-error / stale-while-revalidate policy
**Goal:** Improve availability and tail-latency during upstream instability.

### P2.6 Security execution package (non-IPv6)
**Goal:** Convert security hardening from generic intent to concrete controls.

Planned controls:
- per-client/per-subnet QPS limits,
- optional source ACL mode,
- anti-amplification safeguards for suspicious query patterns,
- auditable deny/reject metrics.

### P2.7 Attack-surface expansion gate (deployment-driven)
**Goal:** Expand to water-torture / amplification defense only when deployment role requires it.

Prioritization policy:
- Recursive/forwarder in controlled networks:
  - keep focus on cache correctness, upstream load protection, and abuse observability first.
  - treat heavy anti-DDoS features as optional add-ons.
- Authoritative-facing or Internet-exposed resolver role:
  - prioritize water-torture controls (random-subdomain miss shaping, negative-response strategy tuning, upstream protection).
  - prioritize amplification controls (open-resolver exposure prevention, response shaping/limiting, ACL defaults).

Acceptance criteria:
- A deployment-role matrix is documented (default profile vs exposed profile).
- Security controls are mapped to role-specific SLO/alert thresholds and benchmark scenarios.

### P2.8 Security hardening
**Goal:** Minimize abuse/risk surface (ACLs, anti-reflection posture, least-privilege runtime).

---

## 3. Upstream Cache Warm-Refresh — Concrete Implementation Plan (for review)

This plan targets Shinku's current architecture (userspace parser/cache pipeline + cleanup thread + admission metadata), and is intentionally incremental.

**Positioning rule (hard requirement):** warm-refresh is an **advanced opt-in component**, disabled by default, and should only be enabled by operators in topologies where upstream cache locality/benefit is validated.

### 3.1 Objectives

1. Reduce latency spikes near TTL expiry for frequently re-requested names.
2. Keep local upstream resolver cache warm for high-value keys.
3. Avoid stampede/amplification side effects.

### 3.2 Scope boundaries (phase 1)

- **In scope:** proactive refresh for selected **positive cache entries**.
- **Out of scope (phase 1):** negative-entry refresh, broad predictive ML scheduling, aggressive stale serving changes.

### 3.3 Eligibility rules (refresh candidate filter)

A cache entry is eligible only if all are true:

1. Entry is currently valid (not expired) and has positive TTL remaining.
2. Entry observed as hot enough:
   - `slot_hot == 1` **or** `slot_hit_count >= refresh_min_hits`.
3. Remaining TTL below threshold:
   - `remaining_ttl <= max(5s, original_ttl * refresh_trigger_ratio)`.
4. Not refreshed too recently:
   - `now - last_refresh_attempt_ns >= refresh_min_interval`.
5. Refresh budget allows (global + per-zone/per-key limits).

Recommended defaults (phase 1):

- `refresh_enabled = false` (explicit opt-in)
- `refresh_trigger_ratio = 0.10` (10% remaining)
- `refresh_min_hits = 2`
- `refresh_min_interval = 5s`
- `refresh_max_qps = 50` (global)
- `refresh_jitter_pct = 20%`

### 3.4 Scheduler model

Add a dedicated low-priority refresh worker thread (or periodic task in existing maintenance loop):

1. Iterate bounded batch of candidate slots each cycle.
2. For each eligible key, compute jittered execution time and enqueue.
3. Execute refresh queries with strict rate limit/token bucket.
4. Store returned response via existing ingest/store path (same validation/admission semantics).

Important: refresh work must never block hot poll loops.

### 3.5 Concurrency and anti-stampede controls

1. **Singleflight per cache key**
   - At most one in-flight refresh per key.
2. **Global token bucket**
   - hard ceiling on refresh QPS.
3. **Per-zone/key cooldown**
   - avoid repeated hammering on unstable answers.
4. **Backoff on upstream failures**
   - exponential backoff for failing key-zone cohorts.

### 3.6 Safety guardrails

1. Skip refresh for very short TTL classes unless explicitly allowed.
2. Keep refresh disabled for negative entries in phase 1.
3. Hard cap refresh queue size; drop low-priority candidates on overflow.
4. Disable feature by default in distributed upstream topologies (e.g., Anycast/LB fan-out) unless explicitly validated.

### 3.7 Metrics (must add with feature)

- `shinku_refresh_attempt_total`
- `shinku_refresh_success_total`
- `shinku_refresh_skip_total{reason=...}`
  - reasons: not_hot, ttl_not_due, cooldown, budget_exceeded, inflight_exists, queue_full
- `shinku_refresh_fail_total{reason=...}`
  - reasons: upstream_timeout, parse_reject, store_reject
- `shinku_refresh_inflight`
- `shinku_refresh_queue_depth`
- `shinku_refresh_upstream_qps`

### 3.8 Rollout plan (phased)

Phase A (dark launch):
- enable candidate evaluation + metrics only, no outbound refresh queries.

Phase B (guarded refresh):
- enable refresh for hot-positive entries with conservative budgets.

Phase C (tuning):
- tune trigger ratio / min hits / QPS with benchmark + soak evidence.

### 3.9 Validation matrix

1. **Hot-key latency tail test:** p95/p99 near TTL boundary improves.
2. **Upstream load test:** refresh overhead bounded by configured QPS.
3. **Churn/attack test:** no refresh stampede under random-subdomain pressure.
4. **Distributed-upstream test:** in Anycast/LB mode, verify warm-refresh remains off and system behavior stays stable.
5. **Soak test:** no queue leak / no unbounded thread/resource growth.

### 3.10 Acceptance criteria for merging

1. Feature is off by default and safe to deploy.
2. All new metrics exported and documented.
3. Unit + integration tests cover happy path and guardrails.
4. 24h soak shows stable memory and bounded refresh QPS.

---

## 4. Risks and explicit non-goals

### Key risks

1. Thundering herd from synchronized TTL boundaries.
2. Refresh traffic becoming amplification of upstream load.
3. Distributed upstream fan-out can nullify prewarm value (refresh affects only a random backend node).
4. Refreshing low-value short-TTL noise instead of hot keys.

### Non-goals for next iteration

- Building full multi-upstream recursive failover orchestration.
- Broad predictive prefetch models before baseline guardrails/metrics are proven.
- Re-introducing ECS-related roadmap scope in the current planning cycle.

---

## 5. Definition of next milestone

Milestone is complete when:

1. Roadmap and code-truth remain aligned.
2. P0.4/P0.5 closure has measurable artifacts (soak + fallback metrics).
3. Warm-refresh phase A/B lands with hard guardrails and observability.
4. Sidecar-mode security baseline progresses without role creep.
