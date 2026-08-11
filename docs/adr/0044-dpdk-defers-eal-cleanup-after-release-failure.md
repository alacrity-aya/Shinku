# DPDK Defers EAL Cleanup After a Release Failure

Status: accepted

`DpdkNativeSession::release()` attempts every independently releasable resource in reverse acquisition order even when
one release fails. It records the first cleanup error for the caller and retains explicit ownership state only for the
resources whose release did not succeed. A later idempotent `stop()` retries only those retained resources rather than
repeating successful releases.

Session does not call `rte_eal_cleanup()` while any pre-EAL DPDK resource remains owned. Calling it at that point would
make the failed release impossible to retry because no DPDK API may be used afterward. Once all ports, queues,
ring-backed ethdevs, rings, Packet Pool state, and other pre-EAL resources have released, Session calls
`rte_eal_cleanup()` exactly once.

Module 9B's Cache and Pending `rte_hash` objects are Backend-owned pre-EAL resources rather than Session members.
ADR-0067 requires Backend to destroy those owners before invoking Session release, so Session never needs to inspect or
own Cache policy merely to enforce this terminal boundary.

The EAL cleanup call remains terminal whether it succeeds or reports failure. Session records that terminal result, and
all later stop or destructor attempts perform no DPDK calls. Fault-injection tests cover each release stage, continued
independent cleanup, selective retry, first-error preservation, deferred EAL cleanup, and the absence of repeated
terminal calls.
