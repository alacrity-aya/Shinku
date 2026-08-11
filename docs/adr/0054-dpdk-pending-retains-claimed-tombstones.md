# DPDK Pending Retains Claimed Tombstones

Status: accepted

The Module 9B DPDK Pending table preserves the eBPF `Active -> Claimed -> cleanup` lifecycle. An eligible Cache Miss
creates an Active Entry. An exact same-Question retransmission may refresh its Query `last_seen` while Active. A
different Question or a Claimed Entry is not refreshed or overwritten. Because the timeout measures inactivity, an
exact Active retransmission refreshes `last_seen` even when the previous inactivity interval has elapsed but bounded
cleanup has not yet removed the Entry.

The first non-expired Response with the reversed tuple and exact complete Question transitions Active to Claimed before
it can authorize one Cache Fill attempt. Claimed Entries suppress every later Response and remain tombstones until
Pending Cleanup removes them at `pending_query_timeout`, measured from the stored Query `last_seen`. This prevents both
duplicate Fill and a delayed Response from an old exchange consuming a rapidly reused tuple-plus-ID.

DPDK preserves the lifecycle semantics without copying eBPF's synchronization mechanism. Client Packet Path, Service
Packet Path, and Pending Cleanup execute serially on the sole lcore, so an ordinary state field and ordered transition
are sufficient; no packed atomic state/time word, CAS retry, mutex, or cleanup thread is introduced. The cooperative
scheduler established by ADR-0045 remains unchanged.
