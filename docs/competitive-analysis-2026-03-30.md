# Shinku Competitive & Business Scenario Analysis (2026-03-30)

## 1. Executive Summary

Shinku's strongest differentiator is not just eBPF performance; it is the combination of **XDP-side cache latency**, **transparent deployment as a sidecar/co-located cache**, and **deterministic operational behavior under stress conditions (truncation, parser guardrails, admission control, ECS compile-time gating)**.

Current codebase has completed the most critical P0/P1 technical baseline for correctness and observability. The next competitive step is to transform this into an **operator-trust product** with clear SLOs, failure-mode controls, and rollout ergonomics for Kubernetes-heavy environments.

---

## 2. Product Positioning: Where Shinku Wins

### 2.1 Ideal Initial Beachhead

Target customer profile (highest near-term win probability):

- Platform teams running Kubernetes at medium-to-large scale.
- Latency-sensitive DNS consumers (service mesh, API gateways, internal control planes).
- Workloads with repeated hot-domain lookups where sidecar-local cache significantly cuts p99 tail.

### 2.2 Practical Value Proposition

1. **Lower DNS tail latency** through XDP cache-hit path.
2. **Reduced upstream resolver load** via on-node cache locality.
3. **Transparent insertion** in front of existing DNS stack (no app code changes).
4. **Deterministic behavior for truncation path** (TC=1 fallback + client TCP retry expectation documented).

### 2.3 What competitors already do well

- CoreDNS/NodeLocal DNSCache: strong Kubernetes integration and ecosystem trust.
- Unbound/dnsdist: mature DNS policy/control-plane knobs.
- Traditional resolvers: long-term operational documentation and proven failure-mode handling.

Shinku must therefore compete on **performance + operational clarity + safe rollout UX**, not raw speed alone.

---

## 3. Current Gaps That Block Competitiveness

## 3.1 Go-to-production gaps (highest priority)

1. **No standardized SLO dashboard package yet** (now partially addressed by added truncation/fallback panels; needs full SLO bundle).
2. **Alert strategy still minimal** (warning-level rules exist; need severity tiers and runbook linkage).
3. **Release hardening workflow missing** (versioned compatibility matrix: kernel/libbpf/clang).

## 3.2 Platform adoption gaps

1. **Kubernetes operational packaging incomplete** (Helm chart/operator-style lifecycle controls).
2. **Canary/rollback ergonomics not codified** (traffic-split and auto-disable policies).
3. **Multi-tenant safety posture needs explicit docs** (resource ceilings, failure isolation, blast-radius guidance).

## 3.3 Commercial readiness gaps

1. No crisp KPI narrative for buyers (e.g., p95/p99 DNS latency reduction, upstream QPS offload).
2. No benchmark corpus across representative environments (veth is good engineering signal but weak buyer signal).
3. No clear migration playbook from NodeLocal/CoreDNS-only setups.

---

## 4. Recommended Strategic Direction (Next 90 Days)

## Phase A (Weeks 1-3): Operator Trust Baseline

Objective: make Shinku safe and understandable in production.

- Deliver a versioned observability pack:
  - dashboards: hit ratio, miss ratio, truncation ratio, fallback efficacy, parser reject reasons, ringbuf drop.
  - alerts: warn/critical tiers with sustained windows.
- Add runbook docs per critical alert.
- Publish failure-mode matrix:
  - upstream unavailable
  - ringbuf pressure
  - abnormal parser reject spikes
  - elevated truncation ratio

Success criteria:

- On-call can triage incidents in <15 minutes with dashboard + runbook only.

## Phase B (Weeks 4-7): Kubernetes Delivery Readiness

Objective: remove adoption friction for platform teams.

- Ship first-class Helm chart/manifests:
  - sidecar or DaemonSet deployment profile.
  - safe defaults for privilege/capabilities and readiness gating.
- Add rollout controls:
  - canary percentage mode,
  - feature flags for observability/admission/ECS compile profile,
  - one-command rollback profile.

Success criteria:

- New cluster can deploy and rollback Shinku without manual BPF troubleshooting.

## Phase C (Weeks 8-12): Buyer Proof & Narrative

Objective: convert technical strength into procurement confidence.

- Produce reproducible benchmark report suite:
  - tail latency (p95/p99), cache-hit efficiency, upstream offload.
  - datasets: hot-domain skew, mixed workloads, truncation-heavy slices.
- Add comparison appendix against baseline NodeLocal/CoreDNS-only path under identical traffic.
- Publish architecture decision records for major tradeoffs (IPv4-only current scope, compile-time ECS toggle, no local TCP synth yet).

Success criteria:

- External reader can evaluate ROI and risk from public docs without source deep-dive.

---

## 5. Prioritized Backlog (Business-Aligned)

P0 (must-have for competitive viability):

1. **SLO dashboard+alerts complete package** (started, finish with runbooks).
2. **K8s deployment artifacts + canary/rollback controls**.
3. **Compatibility/support matrix and release checklist**.

P1 (high leverage):

1. **Workload-profiled benchmarks** with reproducible scripts and reports.
2. **Operational risk docs** for attack/failure scenarios (water torture, amplification, resolver instability).
3. **Automated long-soak pipeline** in CI/nightly with anomaly trend diffs.

P2 (differentiation extensions):

1. Advanced traffic-shaping or adaptive admission heuristics from real-time pressure.
2. Enterprise controls (policy packs, audit traces, profile presets).
3. Extended observability integrations (OpenTelemetry traces/events around control-plane actions).

---

## 6. KPI Framework for Product-Market Fit Validation

Primary KPIs:

- DNS p99 latency improvement vs baseline resolver path.
- Upstream DNS QPS reduction percentage.
- Cache-hit stability under load (hourly variance).
- Incident MTTD/MTTR for DNS path issues.

Guardrail KPIs:

- Truncation ratio sustained threshold breaches.
- TC fallback efficacy degradation duration.
- Parser reject reason spikes (especially malformed/rcode/bad_ecs where enabled).
- Ring buffer drop rates and poll errors.

Adoption KPIs:

- Time-to-first-successful-deploy in K8s.
- Rollback success rate and rollback completion time.

---

## 7. Immediate Implementation Checklist (Next Commit Windows)

1. Expand current observability closeout from warnings to severity-tiered alerts + runbooks.
2. Add `docs/operations/` section (SLO definitions, incident playbooks, rollout policy).
3. Create benchmark report template for internal and external sharing.
4. Ship a minimal K8s deployment package (even if experimental) to validate real-user onboarding flow.

---

## 8. Scope Guardrails (Aligned with Current Direction)

- Keep **IPv6 out of scope** for this phase (explicitly documented and tested as ignored path).
- Keep **sidecar/co-located scenario first**; avoid broad resolver feature creep.
- Maintain **compile-time ECS gating** (default off) to preserve hot-path performance profile.

These guardrails preserve focus and prevent roadmap dilution while competitiveness fundamentals are still being built.
