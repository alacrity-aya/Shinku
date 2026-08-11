# DPDK Backend Owns the EAL Lifecycle

Status: accepted

`DpdkBackend` exclusively owns the process-wide DPDK EAL lifecycle through a private native Session that also owns
ports, queues, and packet pools. EAL initialization occurs inside the Backend `start()` boundary, and Runner-driven
`stop()` performs idempotent reverse-order cleanup after complete or partial startup. `probe()` remains side-effect-free
and therefore cannot initialize EAL or prove runtime ethdev availability. This keeps BackendRunner as the only
production lifecycle controller and avoids introducing EAL initialization into `main()` or a process-global manager;
one Shinku process runs one DPDK Backend Lifecycle and does not promise EAL reinitialization after cleanup.

The call to `rte_eal_cleanup()` is terminal whether it succeeds or reports failure because DPDK forbids later API calls.
The Session records the cleanup attempt before returning its outcome. Any later idempotent `stop()` or Runner destructor
retry returns the recorded outcome without invoking DPDK again.

ADR-0067 extends this ownership order for Module 9B: Backend-owned Cache and Pending `rte_hash` objects are destroyed
before Session release may reach terminal EAL cleanup.
