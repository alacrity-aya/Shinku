# DPDK Drops Frame Contract Violations Locally

Status: accepted

If an RX mbuf violates Module 9's single-segment Frame Contract, the DPDK Backend drops that mbuf locally. It frees the
complete mbuf chain exactly once, continues processing every other packet in the current burst and the opposite
direction, and completes the Poll Quantum successfully.

The first violation emits one `spdlog` warning containing the port identity and observed mbuf metadata. Repeated
violations do not produce per-packet logs. Module 9 does not call `rte_pktmbuf_linearize()`, retry or retain the packet,
forward only its first segment, or convert a packet-local contract violation into `PollFailed`.

This rule is distinct from a malformed or unsupported protocol payload inside a valid single-segment frame, which is a
Cache Bypass and remains eligible for transparent forwarding under ADR-0042. Fake burst tests place contract violations
at the beginning, middle, and end and prove complete-chain release, continued valid-packet forwarding, warning
suppression, and successful Poll Quantum completion.
