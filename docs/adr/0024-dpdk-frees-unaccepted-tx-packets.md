# DPDK Frees Unaccepted TX Packets

Status: accepted

Each Module 9A forwarding direction calls `rte_eth_tx_burst()` exactly once for a received burst. The PMD takes ownership
of the accepted prefix. `DpdkBackend` retains ownership of every unaccepted mbuf and releases those mbufs immediately
before the current Backend Poll Quantum returns. Zero or partial acceptance represents transport congestion and the
Poll Quantum still completes successfully after received packets were consumed.

Module 9A does not spin to retry TX, retain a pending TX queue across Poll Quanta, or introduce a hidden TX buffer. This
keeps packet ownership, stop latency, and partial-failure cleanup bounded and follows DPDK's Basic Forwarding ownership
pattern. A later measured performance decision may introduce buffering, but must explicitly define capacity, overflow,
fairness, shutdown, and Cache Hit packet ownership instead of weakening this contract implicitly.
