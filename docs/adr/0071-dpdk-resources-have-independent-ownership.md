# DPDK Resources Have Independent Ownership

Status: accepted

Module 9 removes the mixed `DpdkNativeSession` boundary. `DpdkBackend` owns four injectable object-oriented resources:
one `DpdkEal`, one shared `DpdkPacketPool`, and one `DpdkPort` for each fixed client/service role. `DpdkEal` owns
process-wide EAL initialization and terminal cleanup. `DpdkPacketPool` owns the shared `rte_mempool`. Each `DpdkPort`
owns one ethdev's configuration, queue setup, promiscuous state, start/stop, burst I/O, and port close.

Backend startup explicitly coordinates the dependency order: initialize EAL, configure both ports and obtain their
adjusted descriptor counts, create the shared Packet Pool, set up both queues, start both ports, then construct the
Cache/Packet Path composition. Backend shutdown destroys scheduler/tasks and Backend-owned Cache/Pending hash owners
first, closes Service then Client, closes the Packet Pool only after both ports have released their resources, and calls
EAL cleanup only after the Packet Pool has released its resource.

Each resource exposes an explicit fallible close operation for the normal `Backend::stop()` path and retries only the
state it still owns. Its destructor calls the same operation as a final safety net and suppresses the unreportable
result. Production resources share a small EAL-owned ownership tracker so a failed port close prevents a destructor
from releasing the shared Packet Pool or terminal EAL state prematurely. The Backend remains the lifecycle owner and
the only object that reports a shutdown error.

The data-plane seam is `DpdkPort`: `receive()` and `transmit()` accept `std::span<rte_mbuf*>`, while packet handles
released by the current owner are passed as non-null `rte_mbuf&`. A nullable cache-context test mode remains local to
`DpdkPacketForwarder`; the production `DpdkBackend` always constructs both paths with a non-null `DpdkCacheContext&`.

This supersedes the private mixed Session ownership wording in ADR-0018, ADR-0026, ADR-0036, ADR-0044, and ADR-0067.
