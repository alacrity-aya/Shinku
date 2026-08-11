# Module 9: DPDK Backend Module

Goal:

- Add the DPDK Backend after common runtime, config, and cache interfaces are stable.

Design status: accepted through Decision 64. Implementation has not started.

Scope:

- Implement minimum configured client-side and service-side DPDK Device Source behavior first.
- Keep eBPF backend runnable.
- Do not reintroduce observability unless explicitly scoped later.
- Introduce pinned `spdlog` 1.17.0 through Meson for minimal synchronous DPDK lifecycle logging; leave the unified
  Runtime Diagnostics boundary and migration of existing output to Module 10.

## Slices

### 9A: DPDK Transport and Lifecycle

- Establish real EAL, port, queue, packet-pool, and Backend Lifecycle ownership.
- Receive and transparently forward packets in both directions between the configured client-side and service-side
  DPDK Device Sources after resolving their runtime Port IDs.
- Keep the MVP on the synchronous Runner/main lcore. Each `poll()` handles one nonblocking burst of at most 32 packets
  per direction, performs immediate TX, and returns to Runner. Internally separate Client and Service Packet Paths from
  the later Cache and Pending Cleanup tasks behind one cooperative scheduler; do not implement them inline as one large
  poll function. Launch no worker lcores or packet-handoff rings. This is an explicit simplicity compromise, not a
  multi-core scaling claim.
- Perform no cache lookup or admission in this slice; every packet follows the forwarding path.
- Forward every frame satisfying the Frame Contract byte-for-byte, including ARP, IPv6, TCP, VLAN, non-DNS, and
  unsupported DNS traffic. Do not add routing, MAC rewriting, protocol filtering, or Cache side effects in 9A.
- Submit each received burst to TX once and immediately free every unaccepted mbuf. Do not retry, retain a cross-quantum
  pending queue, or turn partial TX acceptance into `PollFailed`.
- Require the mandatory two-sided `net_ring` smoke test before starting the Cache Path slice; real PCI evidence remains
  due when suitable hardware is available.

### 9B: DPDK Cache Path

- Add the DPDK concrete Cache Store and direct Data Plane lookup path.
- Use a complete fixed-length, explicitly serialized physical Cache Key in an `rte_hash` index whose data pointers refer
  to a startup-preallocated fixed-capacity Entry slab. Keep Entry ownership, payload storage, cleanup traversal, and
  replacement policy outside `rte_hash`; perform no general heap allocation on Cache Hit or Cache Fill. Treat this as
  the correctness-first MVP baseline and defer representation optimization to `PERF-9B-1`. See
  [ADR-0048](../../adr/0048-dpdk-cache-uses-rte-hash-and-preallocated-entries.md).
- Make every MVP Entry self-contained with fixed worst-case arrays for the 512-byte Response and 45 TTL offsets. Allocate
  one non-growing array of exactly `max_entries` at startup so every hash data pointer stays stable. Use configured
  `max_response_bytes` for admission rather than physical Entry sizing, and defer a split configuration-sized payload
  slab to `PERF-9B-2`. See [ADR-0049](../../adr/0049-dpdk-cache-entries-embed-fixed-payload-storage.md).
- Align Store admission with the eBPF baseline: reclaimed free-list slot, never-used slot, then deterministic
  round-robin Replacement. Same-key Update stays in place without advancing the cursor; expired victims yield
  `Inserted`, while live different victims yield `Replaced`. Keep DPDK single-lcore state free of eBPF-only publication
  synchronization. See [ADR-0050](../../adr/0050-dpdk-store-aligns-admission-with-ebpf.md).
- Give `DpdkCacheStore` one Store-owned mutex covering `store()` and `cleanup()` so it satisfies the shared concurrency
  contract and conformance suite. Keep concrete Cache Hit `lookup()` outside that lock and restricted to the sole
  cooperative lcore; do not infer a cleanup thread or concurrent DPDK lookup guarantee. See
  [ADR-0068](../../adr/0068-dpdk-store-locks-fill-and-cleanup-only.md).
- Use invalidate-first Replacement: erase the victim key before publishing the Candidate. Erase failure preserves the
  victim; Candidate insertion failure after erase leaves the victim lost, reclaims the Entry to the free list, and
  returns non-fatal `WriteFailed`. Do not attempt victim restoration or reserve hidden transactional capacity. See
  [ADR-0051](../../adr/0051-dpdk-replacement-does-not-restore-victim.md).
- Bound DPDK Cache Cleanup to 32 inspected Entry slots per Poll Quantum, with a persistent cursor and remaining count
  across one capacity-wide sweep. This preserves the shared cleanup contract without copying the eBPF cleanup worker's
  256-slot batch onto the packet-processing lcore. Keep the constant private and defer tuning to `PERF-9B-3`. See
  [ADR-0052](../../adr/0052-dpdk-cache-cleanup-scans-32-entries.md).
- Index Pending Queries by the same 16-byte Query-oriented network tuple plus Transaction ID used by eBPF, with each
  `rte_hash` data pointer referring into a startup-preallocated `max_pending_queries` Entry array. Store the complete
  canonical QNAME, QTYPE, and QCLASS in the Entry and compare them exactly; do not introduce a DPDK fingerprint secret
  or put Question identity into the hash key. See
  [ADR-0053](../../adr/0053-dpdk-pending-stores-complete-question.md).
- Preserve the eBPF Pending lifecycle: exact retransmissions refresh Active records, including before delayed cleanup
  after an inactivity timeout; the first non-expired matching Response transitions Active to Claimed before authorizing
  one Fill attempt; Claimed tombstones block refresh, reuse, and duplicate Fill until timeout cleanup. Implement this as
  ordinary single-lcore state, not CAS or a cleanup thread. See
  [ADR-0054](../../adr/0054-dpdk-pending-retains-claimed-tombstones.md).
- Treat Pending capacity exhaustion as Fail-open: do not evict Active or Claimed Entries, do not exceed
  `max_pending_queries`, and do not alter existing state. Forward the Query without Pending state, so its Response cannot
  authorize Fill. See [ADR-0055](../../adr/0055-dpdk-pending-exhaustion-does-not-evict.md).
- Bound Pending Cleanup to 32 inspected Entries per Poll Quantum with its own persistent cursor and remaining count.
  Cache and Pending Cleanup may therefore inspect at most 64 total Entries when both run after the packet paths. Keep
  the constant private and defer larger-batch comparison to `PERF-9B-5`. See
  [ADR-0056](../../adr/0056-dpdk-pending-cleanup-scans-32-entries.md).
- Give Cache Cleanup and Pending Cleanup independent deadlines: `cleanup_interval` and
  `pending_query_timeout / 2`, respectively. Once due, each task continues one 32-Entry batch per quantum until its
  sweep completes, then schedules the next deadline from completion; an error ends the sweep and retries on the next
  normal deadline. Do not share cadence, cursor, remaining count, or deadline. See
  [ADR-0057](../../adr/0057-dpdk-cleanup-uses-independent-deadlines.md).
- Treat cleanup deletion failures as task-local and non-fatal. Retain the failed Entry's ownership, do not return it to
  the free list, continue packet forwarding and the other scheduled task, keep `poll()` successful, and retry the task at
  its next normal independent deadline. Route the failure through suppressed diagnostics rather than per-quantum logs.
  See [ADR-0058](../../adr/0058-dpdk-cleanup-failures-are-non-fatal.md).
- Preserve a cleanup cursor at a failed Entry. End that sweep without advancing past the failure; the next normal
  deadline retries the same Entry, while successful deletion and normal non-expired inspection advance the cursor. Do
  not restart a large sweep at zero or skip the failed owner. See
  [ADR-0059](../../adr/0059-dpdk-cleanup-retries-the-failed-entry.md).
- In the Service Packet Path, perform Response correlation, the Active-to-Claimed transition, and synchronous Cache Fill
  while the RX mbuf remains locally owned; then submit that same mbuf once toward the client for every Store outcome.
  Do not reparse after TX handoff or copy a second Response for Fill in the MVP. See
  [ADR-0060](../../adr/0060-dpdk-fills-before-response-tx-handoff.md).
- On an eligible Client Query Cache Miss, create or refresh Pending from the single parsed Query result before handing
  the original mbuf to service TX. Pending mismatch, exhaustion, or admission failure skips only correlation/Fill; it
  never blocks the Query's one TX submission. Do not copy a work item or access the mbuf after handoff. See
  [ADR-0061](../../adr/0061-dpdk-remembers-pending-before-query-tx.md).
- Reuse the original Query mbuf for a Cache Hit. Build and validate the complete at-most-554-byte frame in fixed scratch,
  adjust the single-segment mbuf to its exact length, then copy the complete frame once and TX it toward the client.
  Length-adjust failure is pre-commit and falls back to Miss/Pending/service forwarding; do not allocate a second mbuf
  or add a runtime fallback path. See [ADR-0062](../../adr/0062-dpdk-cache-hit-reuses-query-mbuf.md).
- Claim a non-expired Pending after exact envelope/tuple/ID/Question correlation but before `DnsPolicy` classification.
  Policy Bypass, Candidate rejection, and Store failure keep the Entry Claimed and do not authorize a later Response;
  forwarding remains unchanged. See [ADR-0063](../../adr/0063-dpdk-claims-before-dns-policy.md).
- Use `clock_gettime(CLOCK_BOOTTIME)` nanoseconds for Cache, Pending, Response observation, and maintenance deadlines so
  suspend consumes TTL and timeout exactly as in eBPF. Do not expose a clock mode or substitute DPDK timer/TSC cycles.
  See [ADR-0064](../../adr/0064-dpdk-uses-boottime.md).
- Read BOOTTIME separately for every packet reaching a Cache/Pending time decision, and once for each bounded cleanup
  batch. Do not reuse a burst- or quantum-start timestamp across packets; defer burst sampling to `PERF-9B-6`. See
  [ADR-0065](../../adr/0065-dpdk-samples-time-per-packet.md).
- Treat a BOOTTIME read failure as local Fail-open degradation. A Client packet skips Cache/Pending work and forwards
  unchanged to service; a Service packet skips claim/Policy/Fill and forwards unchanged to client; a maintenance task
  leaves deadline, cursor, and ownership state unchanged and retries time acquisition in the next Poll Quantum.
  `poll()` remains successful, no stale or alternate clock is used, and each failure category emits at most one warning
  per Backend lifetime. See [ADR-0069](../../adr/0069-dpdk-time-read-failure-is-fail-open.md).
- Generate the same normalized Cache Hit Ethernet/IPv4/UDP/DNS frame as eBPF, including software IPv4 checksum and zero
  IPv4 UDP checksum. Clear inherited offload, packet-type, VLAN, hash, and TX-length metadata before client TX; request
  no PMD offload and expose no device-dependent output variant. See
  [ADR-0066](../../adr/0066-dpdk-cache-hit-normalizes-frame-and-metadata.md).
- After Session establishes EAL, create Cache and Pending `rte_hash` owners, Policy, tasks, and scheduler before start
  succeeds. On normal or partial cleanup, destroy scheduler/tasks and Policy, then Pending and Cache hash owners, before
  Session release can reach terminal EAL cleanup. Keep hash policy outside Session. See
  [ADR-0067](../../adr/0067-dpdk-destroys-hash-owners-before-eal.md).
- Apply the backend-neutral Query Eligibility and Cache Hit Semantics established by Module 8.
- Correlate forwarded misses with Responses, perform Cache Fill and cleanup, and preserve Fail-open forwarding.
- Add Cache Cleanup and Pending Cleanup as separate bounded maintenance tasks in the same single-lcore cooperative
  scheduler. Each invocation performs at most one bounded batch and retains deadline/cursor/continuation state rather
  than draining a complete table in one Poll Quantum.
- Keep Transport Forwarding broader than Cache Eligibility: Bypasses remain byte-preserving and state-free, Cache Misses
  forward upstream, and only a valid Cache Hit consumes a Query and emits a generated client-side Response.
- Keep the eBPF Backend and its current Contract tests runnable.

Module 9 is complete only after both 9A and 9B pass their verification gates. A compile/probe-only DPDK stub is not
an accepted completion state.

Decisions recorded:

- Config binds the two sides of a transparent Cache Point to stable typed DPDK Device Sources. The native Session resolves
  runtime Port IDs after EAL initialization; numeric Port IDs are not configuration. This supersedes ADR-0017; see
  [ADR-0021](../../adr/0021-dpdk-config-binds-device-identity.md).
- Represent those Device Sources as required `[dpdk.client]` and `[dpdk.service]` nested tables. Each selects
  `kind = "pci" | "ring"` and supplies only its kind-specific `address` or `name`; the validated C++ model stores a
  `std::variant<PciDeviceSource, RingDeviceSource>`. Do not accept inline-table or prefixed-string aliases.
- Create every ring Device Source from distinct Session-owned ingress and egress `rte_ring` objects and wrap them with
  `rte_eth_from_rings()`. Do not use the bare EAL `--vdev=net_ringX` loopback topology. Keep ring handles behind an
  internal smoke-test fixture; production callers see only the Backend interface.
- Implement the Backend in two ordered slices: first a real forwarding-only transport/lifecycle slice, then the complete
  DPDK Cache Path. Do not mix initial EAL/port bring-up with Cache semantics debugging.
- `DpdkBackend` exclusively owns EAL, ports, queues, and packet pools through a private injectable native Session.
  Initialize EAL in `start()`, keep `probe()` side-effect-free, perform idempotent reverse-order cleanup in `stop()`, and
  do not promise a second EAL initialization in the same process. See
  [ADR-0018](../../adr/0018-dpdk-backend-owns-eal-lifecycle.md).
- Represent EAL settings as typed TOML Config fields. Do not accept arbitrary `eal_args`, CLI EAL options, or EAL
  environment variables. See [ADR-0019](../../adr/0019-typed-dpdk-eal-configuration.md).
- Support typed physical PCI and virtual DPDK Device Sources. Current mandatory packet-I/O smoke uses a virtual pair;
  record physical smoke as not executed until a two-port host is available rather than treating a hardware skip as
  passing evidence. See [ADR-0020](../../adr/0020-dpdk-supports-physical-and-virtual-devices.md).
- Treat PCI driver binding and kernel-module preparation as deployment policy. Shinku neither binds devices to
  `vfio-pci` nor restores prior drivers; it reports configured BDF and actionable preparation context when EAL cannot
  probe a device. See [ADR-0037](../../adr/0037-dpdk-does-not-manage-pci-driver-binding.md).
- Restrict EAL PCI discovery to configured PCI Device Sources through generated allowlist entries, and use `--no-pci`
  for ring/ring startup. Do not probe unrelated host devices or expose raw allowlist controls. See
  [ADR-0038](../../adr/0038-dpdk-eal-probes-only-configured-pci-devices.md).
- Run each DPDK Backend as an independent EAL primary process. Do not support `auto`, secondary attachment, or shared
  DPDK resource ownership in Module 9. See [ADR-0039](../../adr/0039-dpdk-mvp-is-primary-process-only.md).
- Fix EAL `--file-prefix=shinku` and support one active Shinku DPDK primary per host/runtime directory in the MVP. Do
  not add instance identity Config or automatic PID suffixes. See
  [ADR-0040](../../adr/0040-dpdk-mvp-uses-fixed-file-prefix.md).
- Retain DPDK's default Telemetry socket and native commands. Module 9 adds no custom telemetry command or Backend
  interface and makes no stable schema promise; Module 10 may later adopt it as a Diagnostics adapter. See
  [ADR-0041](../../adr/0041-dpdk-mvp-retains-default-telemetry.md).
- Allow each side to select its Device Source independently, including PCI/vdev mixed pairs. Negotiate port capabilities
  and descriptors independently, enable no optional offloads in 9A, and record non-ring combinations as unverified on
  the current host.
- Use one RX/TX queue pair per port, with queue ID zero. `poll()` performs bounded RX/TX work in both directions on the
  Runner/main lcore and then returns. Runner immediately begins the next iteration after successful quantum completion.
  See [ADR-0034](../../adr/0034-dpdk-mvp-keeps-one-execution-lcore.md).
- Structure runtime work as four bounded tasks behind one private cooperative scheduler: Client Packet Path, Service
  Packet Path, Cache Cleanup, and Pending Cleanup. This separates responsibilities and tests without introducing
  concurrent ownership. See [ADR-0045](../../adr/0045-dpdk-uses-cooperative-bounded-tasks.md).
- Execute every quantum in the fixed order Client Packet Path, Service Packet Path, due Cache Cleanup, then due Pending
  Cleanup. Do not rotate the starting task or let `more_work` move maintenance ahead of packet work. See
  [ADR-0046](../../adr/0046-dpdk-cooperative-scheduler-is-client-first.md).
- Fix the Poll Quantum burst limit at 32 packets per direction. Keep this as an internal constant rather than Config and
  do not adaptively drain additional bursts.
- Treat process CPU affinity as deployment policy rather than DPDK Config. Before EAL initialization, select the lowest
  CPU allowed by `sched_getaffinity()` and map sole MAIN lcore ID zero to it. Expose no CPU/lcore Config fields; the
  benchmark runner is responsible for constraining and recording affinity. See
  [ADR-0034](../../adr/0034-dpdk-mvp-keeps-one-execution-lcore.md).
- Require typed `dpdk.memory_mode = "hugepages" | "no_huge"`. Translate it to private EAL arguments once, never retry
  EAL with a fallback mode, use `no_huge` for mandatory ring/ring smoke, and recommend `hugepages` for physical or mixed
  deployment. See [ADR-0025](../../adr/0025-dpdk-memory-mode-is-explicit.md).
- Request 1024 RX and 1024 TX descriptors per port as internal constants, let each PMD adjust its counts independently,
  retain actual values for queue setup and mempool sizing, and reject adjustment failure or an actual count below 32.
  Do not expose descriptor tuning in Config without physical performance evidence.
- Create one shared DPDK Packet Pool on the MAIN lcore NUMA socket after both ports have adjusted their descriptors. Bind
  both RX queues and the later Cache Hit Path to it; allow remote-socket ports functionally without claiming NUMA-local
  performance. See [ADR-0026](../../adr/0026-dpdk-uses-one-shared-packet-pool.md).
- After each port starts, enable and verify promiscuous mode through the common ethdev API for both PCI and `net_ring`;
  any failure is `StartFailed`. Release the setting during reverse cleanup when the PMD supports it.
- Do not use DPDK Link State as a startup gate. Once port start, queue, Packet Pool, promiscuous, and Frame Contract
  setup succeeds, call `rte_eth_link_get_nowait()` once per port and log the initial state, then enter `Running` even if
  a physical or virtual link is down. Do not query Link State from lifecycle `probe()` or `poll()`, and do not register
  PMD link interrupts or start a monitor thread. Any query error emits one warning and startup continues without retry
  or error classification. See
  [ADR-0030](../../adr/0030-dpdk-link-state-is-not-start-gate.md).
  See also [ADR-0035](../../adr/0035-dpdk-mvp-samples-link-state-once.md).
- Fix the DPDK Frame Contract at a 1500-byte L3 MTU in one mbuf segment, use DPDK's default data room, configure both
  ports for the common MTU, and enable no RX scatter. Do not expose MTU/Jumbo Config or implement multi-segment packets,
  segmentation, or fragmentation. See [ADR-0027](../../adr/0027-dpdk-mvp-uses-standard-single-segment-frames.md).
- Drop an mbuf that violates the Frame Contract, free its complete chain, warn only on the first violation, and continue
  the remaining burst. Do not linearize it or promote the packet-local violation to `PollFailed`. See
  [ADR-0043](../../adr/0043-dpdk-drops-frame-contract-violations.md).
- Derive shared Packet Pool capacity from all adjusted RX/TX descriptor counts plus two 32-packet bursts and a fixed
  256-object lcore cache, rounding up to the smallest fitting `2^N - 1` count with checked arithmetic. Do not expose pool
  size in Config. See [ADR-0026](../../adr/0026-dpdk-uses-one-shared-packet-pool.md).
- Treat `rte_eal_cleanup()` as a terminal boundary whether it succeeds or fails. Record its result and make every later
  cleanup attempt a DPDK-free idempotent result so Runner's destructor retry cannot call DPDK after EAL cleanup.
- During reverse cleanup, continue every independent release after an error but retain failed ownership and defer EAL
  cleanup until all pre-EAL resources release. A later stop retries only retained resources; return the first cleanup
  error. See [ADR-0044](../../adr/0044-dpdk-defers-eal-cleanup-after-release-failure.md).
- Use `spdlog` for low-frequency Shinku DPDK lifecycle and state-transition messages while leaving EAL/PMD diagnostics
  on DPDK's native `rte_log` path. Do not log per packet, per burst, or on every empty Poll Quantum, and do not replace
  typed errors with logs. Call spdlog's global convenience functions directly; do not add logger injection or a logging
  facade in Module 9. See [ADR-0031](../../adr/0031-use-spdlog-for-host-runtime-logging.md).
- Close DPDK Packet Buffer Ownership within one Poll Quantum: TX receives a burst once, accepted mbufs transfer to the
  PMD, and all unaccepted mbufs are immediately freed. Partial acceptance is congestion, not Backend failure. See
  [ADR-0024](../../adr/0024-dpdk-frees-unaccepted-tx-packets.md).

Verification:

- DPDK build path.
- Meson resolves the pinned `spdlog` fallback and a clean build does not require a preinstalled `spdlog` package.
- DPDK-specific smoke tests where available.
- Mandatory virtual-device smoke proves bidirectional packet correctness and lifecycle cleanup; it has no performance
  threshold and must exercise the same ethdev queue/burst path used by PCI devices.
- The ring smoke injects and captures packets through distinct external ring endpoints, proves TX cannot loop back into
  the same Shinku RX path, and covers partial ring/ethdev creation cleanup without exposing handles publicly.
- Transport tests prove byte-for-byte bidirectional forwarding for representative ARP, IPv6, TCP, VLAN, non-DNS UDP,
  malformed DNS, and unsupported DNS frames; 9B tests prove those Bypasses create no Cache or Pending state.
- Fake and virtual-device tests cover zero, partial, and complete TX acceptance without leaks, double frees, retries, or
  `PollFailed` promotion.
- Fake tests cover empty, short, and full 32-packet RX bursts, including both directions full in one Poll Quantum.
- Scheduler tests exercise each task independently and prove per-quantum bounds, outcome aggregation, persisted cleanup
  continuation, and that no task creates a thread, worker lcore, or cross-task packet queue.
- Scheduler trace tests require the fixed client/service/cache/pending order across empty, full-burst, due, and
  `more_work` combinations, including a Query and matching Response arriving in the same quantum.
- Unit tests cover lowest-CPU selection from sparse inherited affinity masks and empty/read-failure mapping without
  mutating the test process's actual affinity.
- Config tests cover required `dpdk.memory_mode`, both accepted values, and missing, mistyped, and unknown values;
  Session tests prove the selected mode produces one EAL initialization attempt with no fallback.
- Config tests cover PCI/PCI, ring/ring, and mixed nested Device Sources; missing side tables, unknown kinds, empty or
  contradictory identity fields, duplicate identities, old numeric Port ID keys, and rejected alternate syntaxes.
- Fake Session tests prove a PCI probe failure retains the configured BDF in `StartFailed` and performs no driver-binding
  operation; physical evidence records the externally prepared driver/PMD state when suitable hardware is available.
- EAL-argument tests cover PCI/PCI, PCI/ring, ring/PCI, and ring/ring discovery sets, including `--no-pci`; resolution
  tests reject missing or duplicate configured PCI devices and prove unrelated BDFs are never emitted.
- EAL-argument tests require `--proc-type=primary` and prove no Config or generated path can select `auto` or secondary.
- EAL-argument tests require the fixed `--file-prefix=shinku`; startup-collision mapping is `StartFailed` and never
  retries with a generated alternate prefix.
- EAL-argument tests prove Module 9 does not emit `--no-telemetry`; no Module 9 test depends on a custom telemetry
  command or treats the DPDK command schema as a Shinku interface.
- Session tests cover unchanged and independently adjusted descriptor counts, PMD adjustment failure, and adjusted RX or
  TX values below Shinku's 32-descriptor support baseline.
- Session tests prove one shared pool is created after descriptor adjustment, both RX queues receive it, and partial
  queue setup releases it exactly once in reverse acquisition order.
- Session tests prove each port is queried exactly once after both ports start and pass promiscuous verification, startup
  succeeds with either or both reported down, and no later `poll()` performs a Link State query or registers a callback.
- Link-query tests prove every negative return logs once, does not skip the other port, does not retry, and never becomes
  `StartFailed`.
- Session/Backend tests cover standard-MTU capability and configuration failure, single-segment forwarding, and complete
  chain release if a fake Session violates the contract by returning a multi-segment packet. Violation tests cover the
  beginning, middle, and end of a burst, one warning only, continued valid forwarding, and successful quantum completion.
- Pool-capacity tests cover the default 8191-mbuf result, asymmetric descriptor adjustment, `2^N - 1` rounding
  boundaries, and checked-arithmetic failure.
- Cleanup fault-injection tests cover every release stage, continued independent cleanup, retained ownership, selective
  retry, first-error preservation, EAL deferral, and exactly one terminal EAL cleanup attempt.
- Use the installed `net_ring` PMD for mandatory virtual-device smoke; do not require rebuilding DPDK with `net_pcap`.
- Existing eBPF/cache/parser tests still pass.
- Module 9B Store tests prove byte-order-stable zero-filled physical-key encoding, inequality across every logical key
  field, full-key collision resolution, stable Entry addresses, startup-bounded storage, allocation-free Hit/Fill,
  same-key Update, expired reuse, live Replacement, bounded cursor cleanup, and hash/Entry rollback on injected errors.
- Entry-layout tests cover maximum Response and 45-offset storage, smaller configured admission limits, active-length
  bounds, poisoned inactive tails, exact `max_entries` allocation, and pointer stability across Update, Replacement, and
  cleanup.
- Run the shared Store conformance suite and focused cross-backend admission vectors proving identical same-key Update,
  free-slot reuse, never-used allocation, round-robin progression, expired-victim `Inserted`, and live-victim
  `Replaced` outcomes for eBPF and DPDK Stores.
- The shared concurrent Store/cleanup conformance case runs against DPDK and proves one Store-owned mutex protects hash,
  owner, free-list, and replacement state without entering concrete lookup; production scheduler tests prove the mutex
  is uncontended and no cleanup thread exists.
- Replacement fault-injection tests prove erase failure preserves victim/cursor/ownership, Candidate publication failure
  never exposes the Candidate, post-erase failure reclaims exactly one slot without restoring the victim, and neither
  path becomes `PollFailed`.
- Cache Cleanup tests cover empty, partial, exactly-32, and multi-quantum capacity sweeps; persistent cursor wrap;
  delayed-expired misses; free-list reclamation; cleanup failure continuation; and fixed scheduler ordering under a
  full packet burst.
- Pending identity tests cover every tuple field and zeroed padding, same-Question retransmission, different-Question
  tuple-plus-ID reuse without overwrite or refresh, reversed Response lookup, exact canonical Question comparison,
  mismatch retention, bounded capacity, stable Entry pointers, and allocation-free runtime operations.
- Pending lifecycle tests cover Active refresh, mismatched non-consumption, expiry boundary, pre-cleanup revival after
  an inactivity timeout, exactly one Active-to-Claimed transition, duplicate Response suppression, Claimed Query
  non-refresh/non-replacement, rapid tuple-plus-ID reuse, and timeout reclamation of both states without atomic or
  threaded execution.
- Pending pressure tests fill the exact configured capacity with Active, Claimed, and mixed populations; prove new
  Queries remain byte-preserving and create no state, no existing Entry or cursor changes, no Response gains Fill
  authorization, cleanup restores capacity, and exhaustion never becomes `PollFailed`.
- Pending Cleanup tests cover empty, partial, exactly-32, and multi-quantum sweeps; independent cursor wrap; Active and
  Claimed timeout boundaries; free-list reclamation; and the combined 32-Cache-plus-32-Pending maintenance bound after
  full packet bursts.
- Deadline tests cover independent initial due times, Cache interval and Pending half-timeout cadence, immediate
  continuation while `more_work` is true, deadline reset only after sweep completion, error-to-next-deadline retry, and
  fixed task order while either or both maintenance sweeps continue.
- Cleanup-failure tests inject Cache and Pending deletion failures, prove ownership/free-list preservation, continued
  packet and opposite-maintenance progress, successful `poll()`, suppressed diagnostics, next-deadline retry, and no
  transition to `PollFailed`.
- Cleanup cursor tests prove failure-point retention, same-Entry retry, successful advancement, no slot reuse before
  deletion succeeds, no restart from zero, and continued opposite-task/packet progress.
- Service Response tests prove one parse, exact Pending claim before TX handoff, synchronous borrowed Candidate
  consumption, Store rejection/error Fail-open forwarding, one TX submission, and no post-handoff access or duplicate
  response.
- Client Query tests prove one eligibility parse shared by lookup and Pending, pre-handoff Pending create/refresh,
  mismatch/exhaustion/error Fail-open forwarding, one service TX submission, same-quantum client-before-service
  correlation, and no post-handoff access or copied work item.
- Cache Hit mutation tests cover shorter, equal, and longer Responses through the 554-byte frame bound; poisoned scratch;
  TTL/checksum completion before mutation; append/trim failure preserving the byte-exact Query and entering Miss;
  one complete post-commit copy; no response allocation; one client TX; and no service TX or Pending on success.
- Claim-boundary tests prove malformed/mismatched/expired Responses retain Active state, the first complete match claims
  before Policy, Policy Bypass and Store rejection/error retain Claimed, duplicates cannot reclassify or refill, and all
  original Responses remain eligible for one transparent TX submission.
- Time tests inject BOOTTIME values around Cache expiry, TTL whole-second aging, Pending refresh/claim/cleanup, suspend-
  equivalent jumps, and maintenance deadlines; they prove no wall, monotonic, DPDK timer, or TSC source enters domain
  arithmetic. Source-failure tests prove Client forwarding without Cache/Pending mutation, Service forwarding without
  claim/Policy/Fill, maintenance retry with unchanged deadline/cursor/ownership, successful `poll()`, no stale or
  fallback clock, and one warning per category per Backend lifetime.
- Sampling tests inject a long pause between packets in one burst and between tasks in one quantum, proving each packet
  observes fresh time while each 32-Entry cleanup batch uses exactly one fresh sample.
- Cross-backend packet vectors require byte-identical normalized Ethernet/IP/UDP/DNS output for DPDK and eBPF Cache
  Hits across discarded Query header fields, TTL ages, Question case, Transaction IDs, and response sizes. DPDK tests
  additionally poison every cleared mbuf metadata field and prove no TX offload flag is requested.
- Composition fault injection covers every boundary after EAL/Session acquisition through scheduler completion and
  proves reverse destruction of tasks, Policy, Pending hash, Cache hash, native ports/pool/rings, and terminal EAL;
  no `rte_hash` operation occurs after EAL cleanup.
