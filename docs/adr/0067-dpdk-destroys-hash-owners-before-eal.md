# DPDK Destroys Hash Owners Before EAL

Status: accepted

Module 9B creates its concrete Cache Store and Pending table only after `DpdkNativeSession` establishes EAL, because
both own `rte_hash` allocations. It then constructs `DnsPolicy`, the four bounded tasks, and the cooperative scheduler
before Backend start succeeds. No production packet poll observes partial composition.

Normal stop and every partial-start unwind destroy the scheduler and tasks, then Policy, then the Pending and Cache hash
owners, before calling `DpdkNativeSession::release()`. Session may invoke terminal `rte_eal_cleanup()` only after those
Backend-owned DPDK allocations are gone. Tests prove that no `rte_hash` operation occurs after EAL cleanup.

Cache and Pending hash policy remains outside Session. Moving these objects into the native resource adapter merely to
make ordering implicit would mix Query, Store, cleanup, and admission semantics into the EAL/port ownership boundary.
