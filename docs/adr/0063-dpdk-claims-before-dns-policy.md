# DPDK Claims Before DNS Policy

Status: accepted

The Module 9B Service Packet Path changes a Pending Entry from Active to Claimed after packet-envelope validation,
reversed tuple and Transaction-ID lookup, complete canonical Question equality, and timeout validation, but before
passing the correlated Response to `DnsPolicy`.

The first complete non-expired match owns the exchange's sole Cache Fill attempt. A later Policy Bypass, zero-lifetime
or oversize rejection, `StoreOutcome::Rejected`, or operational Store failure leaves the Entry Claimed. No later
Response can reclassify the same exchange or retry publication. The original Response remains eligible for its one
transparent client-side TX submission for every Cache result.

Pending therefore authorizes one matching Response rather than one successful Cache publication. This matches the eBPF
TC claim-before-Host-Policy boundary while DPDK omits eBPF-specific ring reservation, event publication, and CAS.
