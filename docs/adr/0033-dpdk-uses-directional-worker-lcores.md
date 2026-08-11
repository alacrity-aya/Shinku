# DPDK Uses Directional Worker Lcores

Status: superseded by [ADR-0034](0034-dpdk-mvp-keeps-one-execution-lcore.md)

Module 9A runs two explicit DPDK data-plane worker lcores in addition to the lcore that executes `BackendRunner` and
supervises the Backend. One worker owns the client-side RX queue and service-side TX queue; the other owns the
service-side RX queue and client-side TX queue. Each worker uses a run-to-completion loop: receive one bounded burst,
perform the configured forwarding work, submit the burst to the destination TX queue exactly once, free every unaccepted
mbuf, and repeat. RX and TX are therefore split by forwarding direction without inserting a per-packet software `rte_ring`
between separate RX-only and TX-only threads.

`DpdkBackend::poll()` remains the synchronous Backend interface visible to `BackendRunner`, but becomes a bounded
supervisor quantum. In this superseded model it checked worker stop/failure state, observed worker progress, and
performed fixed one-second Link State sampling. It did not call `rte_eth_rx_burst()` or `rte_eth_tx_burst()` itself. ADR-0047
also removes the historical `PollStatus` result from the shared Backend interface. `start()`
launches both workers only after all shared resources and queues are ready; `stop()` publishes a stop request, waits for
both workers to leave their loops, then performs reverse-order DPDK cleanup. A worker failure is transferred through a
fixed, thread-safe status channel and becomes `PollFailed` on the next supervisor quantum.

An unexpected exit or nonrecoverable internal failure from either worker is a Backend-wide runtime failure. The
supervisor returns `PollFailed`, and Runner invokes `stop()`, which requests the other worker to stop, joins both, and
then cleans shared resources. Module 9 does not continue with one forwarding direction or restart a failed worker. TX
partial acceptance, Link State down, and Link State query diagnostics are not worker failures.

The model uses exactly three automatically selected CPUs: the lowest three CPUs allowed by the process's
`sched_getaffinity()` mask, with one control/main lcore and two directional workers. No CPU or worker assignment is
Config. Startup fails when fewer than three usable CPUs are allowed. The benchmark must constrain and record all three
CPUs. The current `net_ring` smoke may use any three inherited CPUs; physical NUMA locality remains unclaimed.

This is an explicit DPDK lcore execution model, not an untracked background-thread service. Queue ownership, worker join,
stop ordering, and the worker-to-supervisor failure channel are part of the Backend Lifecycle contract. A separate
RX-only/TX-only pipeline using software rings is deferred because its ownership and backpressure costs are not justified
by the Module 9A two-port MVP.

This model was rejected for the MVP after its worker lifecycle, cross-direction Cache Hit TX ownership, and 9B shared
state requirements proved disproportionate to the immediate goal of establishing a correct DPDK Backend. It remains a
candidate only after the single-lcore implementation produces evidence that execution parallelism is the limiting factor.
