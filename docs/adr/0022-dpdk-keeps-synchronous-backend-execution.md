# DPDK Keeps Synchronous Backend Execution

Status: accepted; reaffirmed as an MVP compromise by [ADR-0034](0034-dpdk-mvp-keeps-one-execution-lcore.md)

Module 9A preserves the existing synchronous Backend contract. `BackendRunner` invokes `DpdkBackend::poll()` on its
current thread, and the DPDK Backend does not launch worker lcores or hidden packet threads. Typed EAL configuration
enables exactly one MAIN lcore, and each configured port uses queue ID zero for one RX and one TX queue. One poll handles
a nonblocking bounded Backend Poll Quantum in both directions and returns success or typed failure, allowing Runner to
check the Stop Condition between quanta. Packet activity remains private because Runner never applied a distinct idle
policy; ADR-0047 removes the former `WorkDone`/`NoWork` result. The MVP quantum performs one RX burst of at most 32 packets per direction, for a maximum of 64 received
packets before control returns to Runner; burst size remains an internal constant rather than Config.

CPU placement is inherited deployment policy rather than Config. Immediately before EAL initialization, Session reads
the process affinity mask, selects its lowest-numbered allowed CPU, and maps sole DPDK MAIN lcore ID zero to that CPU.
Shinku exposes no CPU, lcore-list, core-mask, or worker-core field. Deployments constrain affinity externally, and
benchmark evidence must record that constraint; inability to resolve a usable inherited affinity fails startup.

This deliberately limits the first DPDK implementation to one execution thread. It keeps lifecycle ownership, error
propagation, packet-buffer ownership, and the later 9B Cache Path within the established Backend boundary while the
transport is being proven with virtual devices. Worker lcores and multi-queue scaling remain valid future performance
work, but require explicit benchmark evidence and a later execution-model decision.
