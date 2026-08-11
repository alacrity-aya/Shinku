# DPDK Cleanup Retries the Failed Entry

Status: accepted

When Cache Cleanup or Pending Cleanup cannot delete the Entry at its cursor, it preserves that cursor and ends the
current sweep. The Entry retains ownership and remains unavailable to the free list. At the next normal independent
deadline, the task retries that same Entry first. A successful deletion or a normal non-expired inspection advances the
cursor; cleanup never skips the failed owner and never restarts a large sweep at slot zero.

A permanently failing Entry may consume one capacity slot and produce suppressed diagnostics, but it cannot block the
opposite maintenance task, packet forwarding, or Backend lifecycle. This deterministic retry point is possible because
DPDK owns the cursor locally and cleanup is serialized on the single lcore; no concurrent map cursor or recheck protocol
is required.
