# DPDK EAL Configuration Is Typed

Status: accepted

DPDK EAL settings are part of the validated TOML Effective Config through explicit typed fields. Shinku does not pass
through arbitrary `eal_args`, CLI flags, or environment variables because those inputs would bypass Config Validation,
make device selection and resource ownership implicit, and make Backend Probe/Start behavior difficult to reproduce.
The first supported field set and device-source union are intentionally left for the next Module 9 decision rather than
smuggling deployment-specific EAL options into the initial schema.

CPU placement is deliberately not one of those typed fields. The DPDK Backend consumes the process affinity inherited
from its deployment environment, selects the lowest allowed CPU, and maps sole MAIN lcore ID zero to it. This avoids
duplicating systemd, cgroup, container, or benchmark-runner CPU policy inside Shinku Config.

`dpdk.memory_mode` is a required typed field with `hugepages` and `no_huge` values. It fixes packet-memory backing before
the single EAL initialization attempt; startup never probes one value and falls back to the other.
