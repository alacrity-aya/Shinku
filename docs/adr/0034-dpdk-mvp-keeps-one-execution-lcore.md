# DPDK MVP Keeps One Execution Lcore

Status: accepted, amended by ADR-0070

Module 9 returns to the original single-lcore run-to-completion model. `BackendRunner`, `DpdkBackend::poll()`, and the
private cooperative task scheduler execute on the sole DPDK MAIN lcore. Runtime responsibilities are separate bounded
tasks rather than one monolithic poll implementation: Client Packet Path, Service Packet Path, Cache Cleanup, and
Pending Cleanup. Each Packet Path performs at most one 32-packet RX/TX burst per Poll Quantum; each due maintenance task
performs at most one representation-bounded batch and retains continuation state for a later quantum. Each port has one
RX queue and one TX queue, both queue ID zero, and no DPDK worker lcores or packet-handoff rings are launched. Link State
is observed once during `start()` and never from the Poll Quantum.

Shinku does not generate EAL lcore or affinity arguments. The launch command chooses any required CPU placement using
native EAL arguments; whichever MAIN lcore runs `BackendRunner` owns all packet I/O. Cache Hit responses in 9B can use
the client-side TX queue directly because that same lcore owns all packet I/O.

This is an explicit MVP compromise. It serializes both forwarding directions and packet processing on one lcore and
therefore makes no multi-core scaling claim. The design is chosen to finish and verify EAL ownership,
physical/vdev device resolution, queue setup, mbuf ownership, lifecycle cleanup, and the Cache Path without first adding
worker failure channels, join ordering, cross-lcore Pending/Store synchronization, or additional Cache Hit TX queues.

Directional workers, multiple queues, and software handoff rings remain deferred performance work. Task separation does
not promise that a future implementation can make the tasks concurrent merely by replacing the scheduler. Multi-lcore
execution may be reconsidered only after the complete single-lcore Module 9 implementation and suitable physical-PMD
benchmark evidence identify this execution model as a material bottleneck; a later decision must then define Cache Hit
TX ownership, mbuf handoff and backpressure, shared Cache/Pending concurrency and reclamation, CPU/NUMA placement,
worker failure propagation, and stop/join ordering together.
