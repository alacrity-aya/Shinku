# DPDK Remembers Pending Before Query TX

Status: accepted

On an eligible Cache Miss, the Module 9B Client Packet Path creates or refreshes Pending state before handing the
original Query mbuf to service-side TX. Query Eligibility, concrete Cache lookup, and Pending mutation share one parsed
set of network tuple and complete canonical Question facts while Shinku still owns the mbuf.

Pending Question mismatch, capacity exhaustion, or operational admission failure skips correlation and later Cache Fill
for that exchange, but never blocks or duplicates transparent Query forwarding. The original mbuf is submitted toward
the service exactly once. The Path creates no asynchronous work item and does not read or reparse the mbuf after TX
handoff.

Together with the fixed client-first scheduler order, this guarantees that a Query and matching Response received in the
same Poll Quantum observe Pending creation before Response claim.
