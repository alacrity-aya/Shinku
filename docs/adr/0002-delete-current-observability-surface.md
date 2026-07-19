# Delete Current Observability Surface

Shinku will delete the current Observability Surface during the refactor, including degraded mode, runtime event bus, health/readiness endpoints, Prometheus metrics, BPF counters, dashboard files, and observability tests. Operational Loops required for backend correctness remain: packet-event polling, cleanup scheduling, eBPF attach/detach, signal handling, and shutdown are product behavior, not observability.

**Considered Options**

- Preserve the existing observability code and refactor around it.
- Stub the observability APIs but keep the files and call sites.
- Delete the current observability implementation and reintroduce a cleaner surface later if explicitly scoped.

**Consequences**

The deletion reduces refactor coupling, but temporarily removes runtime health and metrics exports. Code that currently reports errors through degraded mode or metrics must be converted to direct return values, logs, or backend status objects.
