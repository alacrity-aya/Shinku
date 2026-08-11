# DPDK Pending Exhaustion Does Not Evict

Status: accepted

The Module 9B DPDK Pending table never evicts an existing Entry to admit a new Query. When all
`CacheConfig::max_pending_queries` Entries are owned and no reclaimed slot is available, an otherwise eligible Cache
Miss skips Pending creation and forwards the original Query unchanged. Its later Response cannot authorize Cache Fill
without a Pending record.

Capacity pressure leaves every existing Active and Claimed Entry, timestamp, and cleanup continuation unchanged. The
Backend does not round-robin Pending records, search for an Active-only victim, overwrite a Claimed tombstone, or
allocate beyond the Effective Config. Bounded Pending Cleanup eventually restores capacity.

This aligns the ordinary eBPF Pending HASH behavior and preserves Fail-open priority: exhaustion may lose a Cache Fill
opportunity but cannot weaken exact Question correlation or duplicate-Response suppression. A skipped admission is a
private diagnostic fact, not `PollFailed`.
