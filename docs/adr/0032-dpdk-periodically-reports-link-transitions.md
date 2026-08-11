# DPDK Periodically Reports Link Transitions

Status: superseded by [ADR-0035](0035-dpdk-mvp-samples-link-state-once.md)

While the DPDK Backend is running, Module 9 samples both configured ports with the nonblocking ethdev Link State query
at a fixed internal one-second interval. It records each port's initial observed state after startup and subsequently
emits a Runtime Log only when that state changes. A transition to down is a warning, and a transition to up is an
informational message. The interval is not Config in Module 9.

Link sampling is bounded control work within the synchronous Poll Quantum: it never sleeps, waits for negotiation, or
uses a worker thread. Link down does not stop polling, change Backend Lifecycle state, or produce `PollFailed`; packet
forwarding continues according to normal RX/TX results. Link-status-change interrupts are not required because PMD and
virtual-device support is inconsistent and their callback lifecycle would add unnecessary complexity to the MVP.

This supplies basic physical and virtual link diagnostics without putting a log operation on every packet, burst, or
empty Poll Quantum. The behavior complements ADR-0030: startup readiness and runtime visibility remain separate
concerns. Handling failure of the Link State query itself remains an explicit follow-up decision.

This periodic policy was removed from the Module 9 MVP before implementation. ADR-0035 retains only one nonblocking
startup observation; establishing bidirectional packet I/O, mbuf ownership, and cleanup takes priority over runtime
link diagnostics.
