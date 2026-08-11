# DPDK Link State Is Not a Start Gate

Status: accepted

Module 9 treats successful EAL, port, queue, Packet Pool, promiscuous, and Frame Contract setup as sufficient for
`BackendRunner` to enter `Running`. It does not wait for or fail on the PMD-reported physical or virtual DPDK Link State.
Cable/switch negotiation, virtual-device link semantics, hot-unplug, and runtime link flap diagnostics are separate
runtime concerns.

This keeps Backend startup independent from external link timing and makes `net_ring` functional evidence test the same
resource and ethdev queue/burst path without inventing a PHY readiness contract. ADR-0035 permits one nonblocking
startup observation for diagnostics but adds no wait, failure-on-down rule, periodic monitor, or callback.
