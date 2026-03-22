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
- Unit tests for parser, cache correctness, arena list/hash table, hash consistency, integration smoke tests.

### Partially implemented
- ECS handling is scope-zero-only (global cache only).
- CNAME support is ingest-level acceptance; no advanced chain policy controls (loop-depth policy, richer negative interactions).
- TCX attach fallback exists (legacy TC), but no staged rollout/health-gated deployment flow.

### Not yet implemented
- IPv6 fast path (XDP ingress/egress mutation for IPv6).
- Negative caching (NXDOMAIN/NODATA with SOA-derived TTL policy).
- DNS-over-TCP capture/cache strategy.
- Production-grade observability stack (`/metrics`, `/healthz`, `/readyz`, structured counters).
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

### P0.2 Failure-mode policy and graceful degradation
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

---

### P0.3 IPv6 support (end-to-end)
**Goal:** Remove major protocol coverage gap for dual-stack deployments.

**Implement**
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

## P1 (High-value improvements immediately after P0)

### P1.1 Negative caching
**Goal:** Cut upstream load and latency for repeated negative lookups.

**Implement**
- Cache NXDOMAIN/NODATA with SOA-based TTL bounds.
- Separate key semantics for negative entries where needed.
- Add parser rejection/acceptance metrics per negative type.

**Acceptance criteria**
- Unit + integration tests for NXDOMAIN/NODATA.
- TTL expiry behavior matches policy.

---

### P1.2 CNAME hardening and integration coverage
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

## P2 (Strategic scope expansion)

### P2.1 ECS beyond scope-zero
**Goal:** Support subnet-sensitive answers without global-cache correctness risk.

### P2.2 EDNS and large-response strategy
**Goal:** Improve behavior for >512-byte realities while preserving XDP hot-path safety.

### P2.3 DNS-over-TCP handling strategy
**Goal:** Define and implement coherent policy for truncated/large-answer flows.

### P2.4 Advanced admission/eviction policy
**Goal:** Improve hit ratio under skew/churn (e.g., admission filtering, smarter eviction).

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

### Weeks 5-7: IPv6 end-to-end
- XDP/TC/userspace IPv6 path implementation.
- Add unit/integration coverage and packet-level checksum validation.

### Weeks 8-9: Negative caching + CNAME integration suite
- Implement NXDOMAIN/NODATA caching policy.
- Expand integration mock server scenarios for CNAME and negatives.

### Weeks 10-11: Native XDP + soak campaign
- Run native NIC benchmarks.
- Execute 24h/72h soak and churn scenarios.

### Week 12: Release packaging
- Deployment/rollback runbooks.
- Versioned release notes and compatibility matrix.

---

## 4. Definition of “Industrial-Ready v1”

Shinku reaches industrial-ready v1 when all are true:

- P0 items complete and verified.
- SLO instrumentation exists with alertable metrics.
- IPv4 and IPv6 fast paths validated.
- Negative caching operational with TTL policy.
- CNAME integration tests passing in CI + root integration environment.
- Soak tests pass with no critical leaks/crashes.
- Documented rollout and rollback procedures available.

---

## 5. Notes on corrected historical assumptions

- Arena allocation is **not** a pure bump allocator anymore; it is ring-style index progression with slot reuse handling.
- TTL cleanup is **implemented** via background thread and periodic `cleanup_expired_entries`.
- CNAME ingest support is **implemented** with terminal RR gating for A/AAAA query correctness.
- Remaining work focuses on production operations maturity, broader protocol coverage, and release engineering.
