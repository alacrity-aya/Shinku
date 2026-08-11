# DPDK Replacement Does Not Restore Its Victim

Status: accepted

The Module 9B DPDK Store uses the shared Cache Store's invalidate-first Replacement boundary. It removes the selected
victim's complete key from `rte_hash` before publishing the new Candidate. If victim erasure fails, Store leaves the
victim and owner metadata unchanged and returns `WriteFailed`.

If Candidate insertion fails after successful victim erasure, the Candidate never becomes hit-visible, the Entry's
logical ownership is cleared, and the slot is returned to the intrusive free list. The previous victim may already be a
miss. This is explicitly allowed by the shared Store contract and aligns with `EbpfCacheStore` Replacement behavior.
The failure remains Cache-local and Fail-open; packet forwarding continues and Backend polling does not fail.

Module 9B does not attempt to restore the victim with another fallible hash insertion and does not provision a hidden
extra Entry or hash capacity for transactional Replacement. Those alternatives add rollback and double-failure states
without improving DNS correctness, because either loss produces a Cache Miss and preserves upstream resolution.
