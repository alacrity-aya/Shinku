# DPDK Uses Cooperative Bounded Tasks

Status: accepted

Module 9 separates runtime work into four independently testable tasks: Client Packet Path, Service Packet Path, Cache
Cleanup, and Pending Cleanup. One private cooperative scheduler invokes all four on the sole Runner/MAIN lcore and
completes one bounded quantum. `DpdkBackend::poll()` remains the external lifecycle interface and reports only success or
`BackendError`; the task implementations, activity facts, and scheduling policy remain private to the DPDK Backend
module.

Each Packet Path task processes at most one 32-packet RX/TX burst per Poll Quantum. Each due maintenance task performs
at most one representation-bounded cleanup batch and retains its deadline, cursor, and `more_work` continuation across
quanta. ADR-0046 fixes the per-quantum invocation order. No task creates a thread or worker lcore, owns Backend Lifecycle
or Stop Conditions, or communicates through a cross-task packet queue. This gives the implementation responsibility
separation and focused test surfaces while preserving single-thread ownership of ports, queues, mbufs, Cache, and
Pending state.

The task interfaces are not a promise that multi-lcore execution can later be obtained by replacing the scheduler. A
concurrent model may be designed only after complete single-lcore evidence on suitable physical PMDs demonstrates a
material bottleneck. That design must jointly specify TX queue ownership, mbuf handoff and backpressure, Cache
publication and reclamation, Pending concurrency, worker failure propagation, CPU/NUMA placement, and stop/join order.
