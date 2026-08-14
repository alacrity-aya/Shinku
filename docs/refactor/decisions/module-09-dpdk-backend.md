# Module 9 DPDK Backend Decisions

## Segment 21: DPDK Backend

Decisions:

1. Superseded by decision 7. The initial Config exposed distinct numeric `dpdk.client_port` and `dpdk.server_port`
   values as DPDK Ethernet Port IDs.
2. Module 9 is implemented in two ordered slices. 9A establishes real EAL/port/queue/pool ownership and bidirectional
   transparent forwarding with no cache lookup or admission. 9B adds the DPDK concrete Store, Cache Hit Path,
   miss/Response correlation, Cache Fill, cleanup, and shared Cache Contract evidence. Both slices are required before
   Module 9 is complete; a compile/probe-only stub is not an accepted completion state.
3. `DpdkBackend` exclusively owns the process-wide EAL lifecycle through injectable `DpdkEal`, `DpdkPacketPool`, and
   `DpdkPort` objects. `start()` initializes EAL, configures both ports, creates the shared pool, and starts the ports;
   `stop()` closes Service then Client, the pool, and EAL in dependency order, retaining partial ownership for retry.
   `probe()` must not call `rte_eal_init()` or retain DPDK resources, so actual ethdev availability is a `start()` check.
   Production runs one DPDK Backend Lifecycle per process and does not promise EAL reinitialization after cleanup.
   BackendRunner remains the only production lifecycle controller, and tests inject the narrow resource objects.
4. DPDK EAL configuration is represented by explicit typed Config fields. The Backend does not accept an arbitrary
   `eal_args` array and does not read EAL settings from CLI arguments or environment variables. The minimum field set
   and the supported physical/vdev device sources remain the next design decision; every accepted field must be validated
   by Config Loader and be part of the recorded Effective Config.
5. The DPDK Config supports both physical PCI and virtual DPDK Device Sources. The current development host has no pair
   of suitable physical DPDK ports, so mandatory local 9A packet-I/O evidence uses a virtual-device pair. PCI selection,
   capability checks, error mapping, and partial-start cleanup still require deterministic unit/fake coverage, but the
   project must record real PCI smoke as not executed rather than passing or skipping it. Real PCI evidence remains due
   when a two-port host becomes available. The virtual-device smoke is a functional correctness gate with no throughput
   threshold. Device-source-specific code ends after EAL devargs/device creation and capability discovery; configured
   ports share one queue setup, burst packet loop, shutdown, and later Cache Path.
6. Module 9's mandatory virtual-device smoke uses the installed `net_ring` PMD. The test runs within one EAL process,
   injects and captures complete mbufs through named rings in both directions, and proves packet preservation, burst
   ownership, lifecycle cleanup, and partial-failure handling. It has no performance threshold. `net_pcap` is not a
   required PMD and DPDK is not rebuilt merely to add it; tests may still write packet artifacts in pcap format when
   useful. `net_tap` and `net_null` are outside the mandatory correctness transport.
7. Config assigns client-side and DNS-service-side roles to stable typed DPDK Device Sources, not numeric Port IDs.
   After EAL initialization, `DpdkNativeSession` resolves each PCI BDF or supported vdev identity with the ethdev name
   API and retains the resulting Port IDs privately for common queue, burst, and shutdown operations. This supersedes
   decision 1 while retaining its two-port transparent topology. Config Loader rejects the old `client_port` and
   `server_port` keys as unsupported rather than accepting two competing identity models.
8. Client-side and service-side Device Sources are independent and may form PCI/PCI, ring/ring, PCI/ring, or ring/PCI
   pairs. Session performs capability discovery and descriptor adjustment independently for each port, requires only the
   common baseline frame/MTU contract, and enables no optional hardware offloads in 9A. All combinations share one
   packet loop. Current mandatory evidence executes ring/ring; PCI and mixed combinations remain explicitly unverified
   on hardware rather than being reported as passed.
9. Reaffirmed by decision 27. Module 9A keeps the synchronous Backend execution model. `BackendRunner` calls
   `DpdkBackend::poll()` on its current thread; the Backend does not launch worker lcores or hidden packet threads. Each
   port has one RX queue and one TX queue, all using queue ID zero. Typed EAL configuration enables exactly one MAIN
   lcore; `start()` initializes EAL on the Runner thread and the same lcore executes every nonblocking Poll Quantum. One
   poll processes a bounded burst from each direction and then returns so Runner can check the Stop Condition. The
   quantum either succeeds or returns `BackendError`; packet activity is not part of the public result. Decision 42
   later removes the unused `PollStatus` type from the shared Backend interface.
10. EAL cleanup is terminal even when `rte_eal_cleanup()` reports failure. `ProductionDpdkEal` records that the cleanup
    call was attempted before returning its result, and no later `stop()`, destructor, or Runner cleanup retry may invoke
    any DPDK function. A later idempotent `stop()` returns the recorded cleanup outcome without touching DPDK. This makes
    BackendRunner's one destructor retry compatible with DPDK's prohibition on API calls after EAL cleanup.
11. Each forwarding direction submits every received burst to `rte_eth_tx_burst()` exactly once. The PMD takes ownership
    of the accepted prefix; the Backend immediately frees every unaccepted mbuf before the current Poll Quantum returns.
    Partial or zero TX acceptance is normal transport congestion and does not make the Poll Quantum fail. Module 9A has
    no retry spin, cross-quantum pending TX queue, or hidden TX buffer. Fake and `net_ring` tests cover zero, partial,
    and complete TX acceptance and prove each mbuf is transferred or freed exactly once.
12. Module 9 uses a fixed internal RX burst limit of 32 mbufs per direction. One Poll Quantum calls RX once on each side
   and therefore consumes at most 64 packets before returning to Runner. Burst size is not Config in the MVP; fake tests
   cover empty, short, and full 32-packet bursts, including full bursts on both sides in the same quantum. Hardware
   performance evidence may justify a later explicit tuning decision, but the implementation does not adaptively drain
   additional bursts or expose an unsupported tuning knob now.
13. MAIN-lcore CPU placement is inherited deployment policy, not Config. Immediately before EAL initialization, Session
   reads the calling process's `sched_getaffinity()` mask, selects its lowest-numbered allowed CPU, and maps DPDK lcore
   ID zero to that CPU with an explicit EAL lcore mapping; lcore zero is the sole MAIN lcore. Failure to read a nonempty
   usable affinity mask is `StartFailed`. Shinku exposes no `main_cpu`, lcore-list, core-mask, or worker-core Config.
   Deployments use process/cgroup affinity to constrain placement. The benchmark runner must constrain and record its
   affinity for reproducible evidence; functional `net_ring` smoke may inherit the test process affinity.
14. `dpdk.memory_mode` is a required typed Config field with exactly `hugepages` and `no_huge` values. Config Loader
    rejects missing, mistyped, or unknown values before Backend creation, and Effective Config retains the enum. Session
    translates the selected value into its private EAL arguments before the single initialization attempt. It never tries
    one mode and falls back to the other because EAL reinitialization is not promised. Mandatory `net_ring` smoke uses
    `no_huge`; physical and mixed deployment examples use and recommend `hugepages`. Actual Hugepage availability and
    EAL compatibility remain `start()` checks, and failure is `StartFailed` rather than an implicit mode change.
15. Module 9 requests 1024 RX descriptors and 1024 TX descriptors for each port as internal constants, then independently
    passes both requested counts through that port's PMD descriptor-adjustment operation. The adjusted counts may differ
    between ports and are retained privately for queue setup and mempool sizing. Start fails if adjustment fails or any
    actual RX/TX count is below the supported 32-descriptor baseline. Descriptor counts are not Config until physical
    performance evidence demonstrates a tuning need. Tests cover unchanged, independently adjusted, adjustment-error,
    and below-baseline results. The 32-descriptor baseline is a Shinku support decision, not a DPDK correctness rule.
16. Module 9 creates one shared DPDK Packet Pool on the sole MAIN lcore's NUMA socket after both ports have completed
    descriptor adjustment. Both RX queues use that pool, and 9B allocates Cache Hit packets from it. Module 9 does not
    create per-port or per-NUMA pools. A port on another socket remains functionally supported but has no locality or
    performance claim; physical performance evidence records MAIN-lcore, port, and pool NUMA placement. Fake tests prove
    exactly one pool creation, both RX queue bindings, reverse-order release after partial setup, and no pool creation
    before adjusted descriptor counts are known.
17. Module 9's DPDK Frame Contract is fixed at a 1500-byte L3 MTU with one mbuf segment. Both ports are configured for
    and must support that common MTU; the shared Packet Pool uses DPDK's default mbuf data-room size, and RX scatter is
    not enabled. Failure to configure either port for the contract is `StartFailed`. Module 9 exposes no MTU Config,
    Jumbo Frame support, multi-segment forwarding, segmentation, or fragmentation. The backend-neutral Cache Response
    Limit remains 512 bytes, so every eligible Cache Hit plus UDP/IP/Ethernet headers fits the same single-segment
    contract. Tests cover capability/configuration failure and reject any fake multi-segment RX packet without leaking
    its complete segment chain.
18. Shared Packet Pool capacity is derived after descriptor adjustment with no Config knob. The required count is the
    sum of both ports' actual RX and TX descriptor counts, two 32-packet burst allowances, and a fixed 256-object
    single-lcore mempool cache. Session selects the smallest `2^N - 1` count not below that requirement, with checked
    arithmetic and startup failure on unrepresentable capacity. With 1024 RX and 1024 TX descriptors on both ports, the
    pool contains 8191 mbufs. Tests cover that default, asymmetric adjusted counts, rounding boundaries, and overflow.
19. After each port is started, Session enables promiscuous mode through the common ethdev API and verifies success for
    every Device Source, including `net_ring`. Any enable or verification failure is `StartFailed`; Module 9 does not
    infer transparent receive from a Device Source kind or silently accept an unsupported promisc operation. Promisc is
    part of port bring-up and is disabled or released during reverse-order cleanup as supported by the PMD. Tests cover
    both port calls, one-sided failure, and cleanup after the second port's enable fails.
20. Superseded by decision 21. The earlier strict link gate required both ports to report link-up immediately after start.
21. DPDK Link State is not a Module 9 startup gate. After EAL, port, queue, Packet Pool, promiscuous, and Frame Contract
    setup succeeds, `rte_eth_dev_start()` success is sufficient for `BackendRunner` to enter `Running`; Session does not
    wait for or fail on a down physical or virtual link. Link negotiation, hot-unplug, and runtime link flap handling are
    deferred to the Diagnostics/explicit runtime-link decision. This keeps startup independent from cable and switch
    timing while preserving the common ethdev data path. Partial-start cleanup still releases every acquired resource.
22. Module 9 introduces `spdlog` 1.17.0 as the Host Runtime logging implementation through a pinned Meson WrapDB wrap.
    It may emit a small synchronous set of DPDK lifecycle and state-transition messages, while DPDK EAL/PMD diagnostics
    remain native `rte_log` output. Logging never replaces `BackendError` control flow and is forbidden per packet, per
    burst, and on every empty Poll Quantum. Module 10 still owns common routing, formatting, and migration of existing
    output; choosing the library does not implicitly select an asynchronous logger.
23. To keep Module 9 focused on the DPDK Backend, its code calls `spdlog::info()`, `spdlog::warn()`, and
    `spdlog::error()` directly through spdlog's process-global default logger. Module 9 adds no logger constructor
    parameters, custom logging facade, or diagnostic sink. Module 10 may revisit this global access model when it
    centralizes Host Runtime diagnostics.
24. Superseded by decision 28. The earlier design sampled both ports' Link State with a nonblocking ethdev query at
    one-second intervals. It logged each initial observed state, then logged only transitions: down was a warning and up
    was informational. Sampling never slept or launched a worker, and link down did not change Backend Lifecycle state,
    stop polling, or become `PollFailed`. The interval was not Config and did not require PMD link-status-change
    interrupt support.
25. Superseded by decision 27. Module 9A temporarily selected the explicit directional-worker execution model in
    ADR-0033. After shared startup completed, `start()` launched one DPDK worker per forwarding direction and retained
    the Runner/main lcore as supervisor. Each worker owned one RX/TX queue pair across the two ports and performed
    run-to-completion forwarding; `poll()` checked worker progress/failure and Link State but did no packet I/O. `stop()`
    signaled both workers, waited for both lcores,
    and only then performs reverse-order DPDK cleanup. The lowest three usable CPUs in the inherited affinity mask are
    selected automatically; fewer than three is `StartFailed`. No worker/lcore fields are Config.
26. Superseded by decision 27 because the MVP has no worker lcores. Under the rejected directional-worker model, either
    worker's unexpected exit or nonrecoverable internal failure was a Backend-wide failure. The worker published a fixed
    failure status, the supervisor's next `poll()` returned `PollFailed`, and Runner called `stop()` to request and join
    the other worker before shared cleanup. Module 9 does not run one-sided or restart a
    failed worker. TX partial acceptance and Link State outcomes remain governed by their separate non-fatal decisions.
27. Module 9 returns to decision 9's one-lcore model as an explicit MVP compromise. The Runner/main lcore performs one
    bounded RX/TX burst per direction inside each Poll Quantum; both ports keep only RXQ0 and TXQ0. CPU selection again
    chooses the lowest single usable CPU from inherited affinity. No worker lcores, worker failure channel, join protocol,
    cross-worker ring, or extra Cache Hit TX queue is implemented. This simplifies 9A
    and 9B correctness and lifecycle work but makes no multi-core scaling claim. Reconsidering directional workers
    requires complete single-lcore performance evidence and one design covering Cache Hit TX ownership, shared Cache
    and Pending concurrency, worker failure propagation, and stop ordering. See ADR-0034.
28. Module 9 calls `rte_eth_link_get_nowait()` exactly once for each port during `start()`, after both ports have started
    and passed promiscuous-mode verification. It logs each initial up/down result, but down never delays or fails startup.
    This cannot live in lifecycle `probe()` because EAL and runtime Port IDs do not yet exist there. After the startup
    observation, Module 9 performs no Link State queries, callback registration, monitor component, or monitor thread.
    See ADR-0035.
29. Any negative result from the one-time `rte_eth_link_get_nowait()` call is diagnostic-only. Module 9 logs one warning
    with the port identity and DPDK error, continues to query the other port, and continues startup. It performs no
    retry, error classification, or `StartFailed` promotion. This applies equally to `-ENOTSUP`, `-ENODEV`, `-EINVAL`,
    and other PMD query errors; prior successful port setup remains the transport startup authority.
30. DPDK Device Sources use required nested typed TOML tables, `[dpdk.client]` and `[dpdk.service]`. Each table contains
    `kind = "pci" | "ring"` and exactly one kind-specific identity field: PCI requires a nonempty `address` BDF and
    forbids `name`; ring requires a nonempty `name` and forbids `address`. The C++ Config model represents each side as
    `std::variant<PciDeviceSource, RingDeviceSource>`, so numeric Port IDs and raw devargs never cross the Config seam.
    Config Loader rejects missing side tables, unknown kinds, missing or contradictory kind-specific identity, duplicate
    client/service identity, and the superseded `dpdk.client_port` or `dpdk.server_port` keys. Inline tables and prefixed
    strings such as `ring:shinku-client` are not alternate accepted syntaxes. See ADR-0021.
31. A ring Device Source is created explicitly by `DpdkNativeSession`, not by passing a bare `--vdev=net_ringX` to EAL.
    For each configured ring side, Session creates distinct ingress and egress `rte_ring` objects and wraps them in one
    ethdev with `rte_eth_from_rings()`. This prevents the default net_ring loopback topology from feeding transmitted
    packets back into the same Shinku RX path. After ethdev creation, ring and PCI ports share capability discovery,
    port/queue setup, burst forwarding, and cleanup sequencing. Ring handles never cross the production Backend
    interface. The mandatory in-process smoke uses an internal test fixture to enqueue packets into each ingress ring
    and dequeue packets from each egress ring, proving both forwarding directions through the real ethdev burst path.
    Session owns and releases every ring-backed ethdev and ring exactly once in reverse acquisition order. See ADR-0036.
32. PCI kernel-driver binding is a deployment prerequisite, not part of the DPDK Backend Lifecycle. Shinku does not run
    `dpdk-devbind`, write PCI driver sysfs attributes, load kernel modules, detach an active Linux interface, force
    `vfio-pci`, or attempt to restore a prior driver during shutdown. The deployment environment prepares each configured
    BDF according to its PMD, including retaining the kernel driver for a bifurcated PMD when required. Session only gives
    configured PCI identities to EAL and resolves the resulting ethdevs. If EAL cannot probe a configured device, startup
    returns `StartFailed` containing the BDF, the available DPDK error, and an operator hint to verify driver binding,
    permissions, IOMMU/VFIO state, and PMD availability. See ADR-0037.
33. EAL PCI discovery is restricted to the PCI Device Sources in the validated Config. Session emits one EAL allowlist
    entry for each configured PCI BDF, emits no unconfigured PCI identity, and uses `--no-pci` for a ring/ring topology.
    PCI/ring and ring/PCI therefore probe exactly one PCI device; PCI/PCI probes exactly the two distinct configured
    devices. After EAL initialization, every configured PCI identity must resolve to exactly one ethdev and every ring
    identity is created explicitly under decision 31. Missing, duplicate, or unexpected resolution is `StartFailed` and
    triggers normal partial-start cleanup. Module 9 exposes no probe-all switch or raw allowlist Config. See ADR-0038.
34. Every Module 9 DPDK Backend runs as one independent EAL primary process. Session explicitly selects
    `--proc-type=primary`; it never uses `auto`, never starts as a secondary, and exposes no process-type Config. The
    Backend does not attach to another process's EAL resource domain or share its ports, memory, rings, Packet Pool,
    Cache Store, or cleanup responsibility. If primary initialization cannot establish the instance's own resource
    domain, startup fails instead of changing process role. DPDK multi-process support requires a future design covering
    shared-memory identity, resource discovery, ownership, Cache concurrency, failure propagation, and shutdown. See
    ADR-0039.
35. Module 9 fixes the EAL file prefix at `shinku` and supports only one active Shinku DPDK primary per host/runtime
    directory. It does not derive a PID suffix and exposes no `instance_name` or `file_prefix` Config. A second instance
    that collides with the active `shinku` EAL resource domain fails startup; Shinku does not attach to it or silently
    choose another prefix. Supporting concurrent independent primaries requires an explicit future deployment identity
    decision together with resource-directory, hugepage-file, diagnostics, and operational cleanup semantics. See
    ADR-0040.
36. Module 9 retains DPDK's default Telemetry service. Session does not pass `--no-telemetry`, so EAL may create its
    standard telemetry socket under the fixed `shinku` runtime directory and expose the commands provided by the linked
    DPDK libraries and PMDs. Shinku registers no custom telemetry commands, wraps no telemetry client in the Backend
    interface, promises no stable DPDK command schema, and does not replace typed errors or `spdlog` lifecycle messages
    with telemetry. Socket availability and permissions remain deployment/runtime facts. Module 10 may later decide
    whether DPDK Telemetry becomes a documented Diagnostics adapter. See ADR-0041.
37. DPDK Transport Forwarding is broader than the Cacheable Query Profile. Every received Ethernet frame that satisfies
    the Module 9 single-segment Frame Contract is forwarded byte-for-byte to the opposite port unless an eligible Query
    is answered by the Cache Hit Path. ARP, IPv6, TCP, non-DNS UDP, VLAN-tagged traffic, malformed or unsupported DNS,
    and every other Cache Bypass are forwarded without creating Cache, Pending, or Fill state. Module 9 performs no MAC
    rewriting, routing, bridging table, ACL, protocol allowlist, or non-DNS filtering. Cache Misses and Bypasses preserve
    the upstream path; only a valid Cache Hit consumes the Query and transmits a generated Response toward the client.
    Tests prove byte preservation in both directions and state-free forwarding for representative non-cacheable frames.
    See ADR-0042.
38. An RX mbuf that violates the single-segment Frame Contract is dropped locally rather than failing the Backend or
    being linearized. Session frees the complete mbuf chain exactly once, continues processing every other mbuf in the
    burst and the opposite direction, and completes the Poll Quantum successfully. The first
    such violation emits one `spdlog` warning with the port identity and observed metadata; repeated violations are
    suppressed rather than logged per packet. Module 9 does not call `rte_pktmbuf_linearize()`, retry the packet, forward
    a partial first segment, or return `PollFailed`. Fake tests cover violations at the beginning, middle, and end of a
    burst and prove complete-chain release plus continued valid-packet forwarding. See ADR-0043.
39. `DpdkBackend::stop()` closes each independently releasable Port, then the shared Packet Pool, then EAL, even after
    one step fails. Each resource records the ownership state needed for a later retry; the first cleanup error is
    returned to BackendRunner. EAL cleanup is not attempted while a Port or Packet Pool still owns resources. Once all
    pre-EAL resources have released, `ProductionDpdkEal` calls `rte_eal_cleanup()` exactly once; that call is terminal
    whether it succeeds or fails. Subsequent stop/destructor attempts return the recorded terminal result without
    repeating terminal DPDK calls. See ADR-0044 and ADR-0071.
40. Module 9 separates DPDK runtime work into four independently testable bounded tasks: Client Packet Path, Service
    Packet Path, Cache Cleanup, and Pending Cleanup. One private cooperative scheduler invokes them on the sole
    Runner/MAIN lcore; `DpdkBackend::poll()` remains the external lifecycle interface and does not contain the four
    implementations inline. Tasks own no threads, lcores,
    Stop Conditions, Backend Lifecycle, or cross-task queues. The two Packet Path tasks each process at most one
    32-packet RX/TX burst per quantum; each due maintenance task performs at most one representation-bounded cleanup
    batch and carries deadline/cursor/`more_work` state across quanta. This is responsibility separation without
    concurrent execution. A future multi-lcore model is not promised to reuse the task interfaces unchanged and may be
    reopened only with suitable physical-PMD and single-lcore performance evidence plus a complete design for TX queue
    ownership, mbuf handoff/backpressure, Cache publication/reclamation, Pending concurrency, worker failure, CPU/NUMA,
    and stop/join ordering. See ADR-0045.
41. Every cooperative Poll Quantum uses the fixed order Client Packet Path, Service Packet Path, Cache Cleanup when due,
    then Pending Cleanup when due. Client-first is a Query Correlation rule as well as a scheduling preference: an
    eligible Query publishes or refreshes its Pending record before a Response consumed later in the same quantum can
    attempt to claim it. Both Packet Paths always receive their one-burst opportunity before maintenance. Each due
    maintenance task receives at most one bounded batch in the same quantum; Cache and Pending do not alternate order,
    drain to completion, or move ahead of packet work when `more_work` is true. Since every task has a strict per-quantum
    bound and Runner immediately invokes the next quantum, the fixed order guarantees progress without round-robin
    start-state machinery. See ADR-0046.
42. `PollStatus` is removed from the shared Backend interface because `BackendRunner` never consumed `WorkDone` versus
    `NoWork` and deliberately applied identical pacing to both. `Backend::poll()` now returns
    `std::expected<void, BackendError>`: success means one bounded Backend Poll Quantum completed, regardless of whether
    it processed packets, advanced cleanup, waited until timeout, or was interrupted without work; failure means the
    Backend cannot continue. eBPF retains its private event counts and maps timeout/`EINTR` to success, while genuine
    readiness/consume failures still return `BackendErrorCode::PollFailed`. DPDK task results remain private where
    required for deadlines, cursors, continuation, ownership, and focused tests. Diagnostics must expose meaningful
    backend-specific counters rather than reintroducing a binary activity result at the lifecycle seam. See ADR-0047.
43. The Module 9B MVP concrete Store uses one DPDK `rte_hash` index from a complete fixed-length physical Cache Key to
    a stable `DpdkCacheEntry*` in a startup-preallocated fixed-capacity Entry slab. The physical key explicitly encodes
    Cache Namespace, QTYPE, QCLASS, canonical QNAME length, and the complete canonical QNAME into a zero-filled,
    byte-order-stable buffer; it never hashes a C++ object representation with implicit padding. `rte_hash` owns and
    compares the complete key but owns neither the pointed-to Entry nor its lifetime. Each occupied Entry retains its
    physical key for deletion and owns its response, TTL offsets, timestamps, and private replacement/cleanup metadata.
    Startup allocates the hash, Entry slab, and all bounded backing storage; Cache Fill and Cache Hit perform no general
    heap allocation. This is the correctness-first MVP baseline, not a claim that large-key hashing is optimal.
    `PERF-9B-1` owns any later comparison with a compact fingerprint index or a custom fixed-capacity open-addressing
    table; no alternative may replace complete-key equality with probabilistic identity. See ADR-0048.
44. Each MVP `DpdkCacheEntry` is self-contained and fixed at the protocol worst case: it embeds the complete physical
    key, timestamps and private metadata, a 512-byte Response array, and a 45-element `uint16_t` TTL-offset array.
    `CacheConfig::max_response_bytes` remains the admission limit but does not shrink the physical Entry. Store startup
    allocates one fixed-size, non-growing Entry array of exactly `max_entries`; `rte_hash` data pointers refer into that
    array and therefore remain stable for the Store lifetime. Active sizes bound every read and write, and inactive
    array tails are non-semantic and are never emitted, parsed, hashed, or required to be cleared. This Array-of-Entries
    layout is the simplest allocation-free MVP, not a memory-density claim. `PERF-9B-2` may compare a configuration-sized
    split payload slab only after measured memory/cache pressure justifies its layout arithmetic and extra indirection.
    See ADR-0049.
45. The DPDK Store aligns its admission and victim-selection semantics with `EbpfCacheStore`: allocate reclaimed slots
    from an intrusive free list first, then the never-used suffix, and only then select the Entry at a deterministic
    round-robin replacement cursor. A same-key Candidate updates its existing Entry in place, returns `Updated`, and
    does not advance replacement selection. A new key using an empty or cleanup-reclaimed slot returns `Inserted`.
    Reusing a selected expired victim also returns `Inserted`; displacing a still-hit-visible different victim returns
    `Replaced`. Successful occupied-slot selection advances the cursor to the following slot. DPDK aligns these
    observable Store outcomes and ordering rules but does not copy eBPF-only generation, seqlock, or BPF publication
    machinery into the single-lcore MVP. Decision 63 separately retains the shared Cache Store contract's writer/cleanup
    mutex. Admission-policy optimization remains governed by `PERF-8D-1` and requires backend-specific evidence rather
    than semantic drift. See ADR-0050.
46. DPDK Replacement uses the shared Store's permitted invalidate-first failure boundary. It first removes the selected
    victim's complete key from `rte_hash`; an erase failure leaves the victim and owner state unchanged and returns
    `WriteFailed`. After a successful erase, failure to add the new key returns `WriteFailed`, leaves the Candidate
    unpublished, clears the Entry's logical ownership, and places the slot on the free list. The old victim may therefore
    already be a miss, exactly as the Cache Store contract permits. Module 9B does not attempt a fallible second hash
    operation to restore the victim and does not reserve a hidden extra Entry or hash capacity for transactional
    replacement. This error remains Cache-local and Fail-open rather than becoming `PollFailed`. See ADR-0051.
47. The DPDK Cache Cleanup task inspects at most 32 Entry slots per Poll Quantum. It retains a persistent cleanup cursor
    and remaining-count state so one cleanup sequence covers exactly one capacity-wide sweep and reports private
    continuation until that sweep completes. Expired Entries are removed from `rte_hash` and returned to the intrusive
    free list; Hit-time expiry remains authoritative while reclamation is delayed. DPDK aligns eBPF cleanup semantics
    but deliberately does not copy eBPF's 256-slot batch, because eBPF cleanup runs on a separate worker while DPDK
    maintenance shares the sole lcore with both 32-packet paths. The constant is private, not Config. `PERF-9B-3` may
    compare larger fixed batches only with packet latency, sweep completion, capacity pressure, and total CPU measured
    together. See ADR-0052.
48. DPDK Pending Query indexing preserves the eBPF correlation identity but uses exact Question storage. One `rte_hash`
    key is the same 16-byte Query-oriented network-order tuple used by eBPF: client/source IPv4 and UDP port,
    service/destination IPv4 and UDP port, DNS Transaction ID, and explicit zeroed padding. It contains no Question,
    ifindex, protocol discriminator, or duplicate Cache Namespace. The associated pointer refers into a startup-
    preallocated array of exactly `max_pending_queries` Entries. Each Entry retains the complete canonical QNAME, QTYPE,
    QCLASS, state, and last-seen time. An existing tuple-plus-ID with a different complete Question is not overwritten or
    refreshed, and a mismatched Response does not consume it or authorize Fill. This keeps eBPF's one-exchange-per-tuple
    trust boundary while replacing its keyed 128-bit Question fingerprint with exact equality; DPDK therefore needs no
    fingerprint secret for Pending. `PERF-9B-4` may compare compact Question storage only without changing correlation
    behavior or allowing probabilistic equality to authorize Fill. See ADR-0053.
49. DPDK Pending Queries preserve the eBPF `Active -> Claimed -> cleanup` lifecycle. An eligible Cache Miss inserts an
    Active Entry; an exact same-Question retransmission refreshes its `last_seen` while Active, including when the prior
    inactivity interval has elapsed but cleanup has not removed the Entry. The first
    non-expired matching Response changes the Entry to Claimed before it can authorize a Cache Fill attempt. Claimed
    Entries reject Query refresh/replacement and suppress every later Response. Active and Claimed Entries both remain
    resident until Pending Cleanup removes them at `pending_query_timeout` measured from the stored Query `last_seen`.
    The tombstone prevents duplicate Fill and delayed old Responses from consuming a rapidly reused tuple-plus-ID.
    Because Client Packet Path, Service Packet Path, and Pending Cleanup execute serially on one lcore, DPDK uses an
    ordinary state field and ordered transition rather than eBPF's packed atomic word and CAS. This semantic alignment
    does not add a cleanup thread or reopen ADR-0045's cooperative scheduler. See ADR-0054.
50. DPDK Pending capacity exhaustion is Fail-open and performs no eviction. If all `max_pending_queries` Entries are
    owned and no free-list slot exists, an otherwise eligible Cache Miss skips Pending creation and still forwards the
    original Query to the service. Existing Active and Claimed Entries, their timestamps, and cleanup state remain
    unchanged; the later Response cannot authorize Fill without a Pending record. Module 9B does not round-robin evict
    Pending, search for an Active-only victim, overwrite Claimed tombstones, or provision capacity beyond the Effective
    Config. This aligns the bounded ordinary eBPF HASH behavior: pressure may reduce Fill opportunity but cannot weaken
    Question correlation or duplicate suppression. Capacity skips are private diagnostic facts and never `PollFailed`.
    See ADR-0055.
51. The DPDK Pending Cleanup task inspects at most 32 Entry slots per Poll Quantum. It owns a cursor and remaining-count
    state independent of Cache Cleanup, so one Pending cleanup sequence covers exactly one capacity-wide sweep across
    bounded invocations. When both maintenance tasks run in the same fixed-order quantum, Cache and Pending therefore
    inspect at most 64 total slots after the two packet paths. This does not copy eBPF's 256-record batch because its
    cleaner runs on a separate worker. The constant is private, not Config, and cleanup delay affects reclamation rather
    than correlation correctness because Response handling checks timeout before claim. `PERF-9B-5` may compare larger
    fixed batches only with packet latency/loss, Pending pressure, correlation success, sweep completion, and CPU
    measured together. See ADR-0056.
52. Cache Cleanup and Pending Cleanup each own an independent maintenance deadline. Cache first becomes due at the
    configured `cleanup_interval`; Pending first becomes due at `pending_query_timeout / 2`. Once a task starts a
    capacity-wide sweep, `more_work` keeps it due and the scheduler runs one 32-slot batch on every following quantum
    until that sweep completes. Only then does the task schedule its next deadline from the completion time; an error
    ends the current sweep and the task retries at the next normal deadline. The two tasks never share a cadence,
    cursor, remaining count, or deadline. This preserves eBPF cleanup timing semantics while keeping each DPDK quantum
    bounded and the fixed Client, Service, Cache, Pending order unchanged. See ADR-0057.
53. A DPDK Cache or Pending cleanup deletion failure is task-local and non-fatal. The task retains the failed Entry's
    ownership and does not return it to the free list, continues the remaining packet/task schedule, and keeps
    `Backend::poll()` successful. The failure is recorded through the diagnostic/logging path with suppression rather
    than emitted on every quantum. The task ends its current sweep and retries at its next normal independent deadline;
    packet forwarding, Cache Hit expiry checks, Pending correlation, and Backend Lifecycle state are unchanged. This
    preserves the Cache Store Fail-open contract and eBPF CleanupWorker behavior. See ADR-0058.
54. When a DPDK Cache or Pending cleanup deletion fails, the task preserves its cursor at that Entry and ends the current
    sweep. The next normal deadline begins by retrying the same Entry; only a successful deletion or a normal non-expired
    inspection advances the cursor. The failed owner remains out of the free list. This avoids skipping reclaimable
    capacity and avoids restarting a large sweep from slot zero. A permanently failing Entry may retain one capacity
    slot and emit suppressed diagnostics, but cannot block packet forwarding, the opposite maintenance task, or the
    Backend lifecycle. See ADR-0059.
55. The DPDK Service Packet Path completes Response correlation, the `Active -> Claimed` transition, and synchronous
    Cache Fill before handing the original RX mbuf to TX. It parses the Response once and consumes borrowed Candidate
    spans while Shinku still owns the mbuf; then it submits that same mbuf exactly once toward the client regardless of
    Store `Inserted`, `Updated`, `Rejected`, or operational failure. A Store result never blocks or duplicates transparent
    forwarding, and no post-TX reparse or Response copy is introduced in the MVP. This is the DPDK equivalent of the
    eBPF path completing correlation/event publication before the packet leaves the forwarding path. See ADR-0060.
56. On an eligible DPDK Cache Miss, the Client Packet Path creates or refreshes Pending state before handing the original
    Query mbuf to service-side TX. Query Eligibility, concrete Cache lookup, and Pending mutation consume one parsed set
    of tuple and complete Question facts while Shinku still owns the mbuf. Pending mismatch, capacity exhaustion, or an
    operational admission failure only skips correlation for that exchange; the original Query is still submitted once
    toward the service. The Path neither copies a Pending work item nor reads or reparses the mbuf after TX handoff. The
    accepted client-first scheduler order therefore establishes Pending before a matching Service Response handled
    later in the same Poll Quantum can claim it. See ADR-0061.
57. A DPDK Cache Hit reuses the original Query RX mbuf rather than allocating a second mbuf. Before mutation, Client
    Packet Path constructs and validates the complete at-most-554-byte Ethernet/IPv4/UDP/DNS Response in one fixed
    task-owned scratch buffer, including Hit semantics, aged TTLs, lengths, and checksum. It then uses the checked
    single-segment `rte_pktmbuf_append()` or `rte_pktmbuf_trim()` operation to reach the exact frame length; failure is
    pre-commit, leaves the Query unchanged, and falls back to the ordinary Miss/Pending/service-forwarding path. After a
    successful length adjustment, or immediately for equal length, one bounded copy replaces the complete frame and no
    later construction operation may fail. The same mbuf is submitted once toward the client. Module 9B allocates no
    per-Hit response mbuf and provides no allocate-on-tailroom-failure fallback. See ADR-0062.
58. DPDK Pending claim occurs after packet-envelope validation, reversed tuple/Transaction-ID lookup, complete Question
    equality, and timeout validation, but before `DnsPolicy` classifies the correlated Response. The first such Response
    changes Active to Claimed and owns the exchange's sole Fill attempt. A subsequent Policy Bypass, zero-lifetime or
    oversize rejection, `StoreOutcome::Rejected`, or operational Store failure leaves the tombstone Claimed while the
    original Response still forwards. Pending therefore authorizes one complete matching Response, not one successful
    cache publication. Module 9B does not delay claim until Candidate construction or Store success. This matches the
    eBPF TC claim-before-Host-Policy boundary without copying its ring reservation or CAS mechanism. See ADR-0063.
59. DPDK Cache Time, Pending Time, Response Observation Time, and maintenance deadlines use nanoseconds from
    `clock_gettime(CLOCK_BOOTTIME)`. Suspend therefore consumes Cache TTL, Pending inactivity timeout, and cleanup
    intervals, matching the eBPF `bpf_ktime_get_boot_ns()` semantic domain. Module 9B does not use
    `CLOCK_MONOTONIC`, wall time, `rte_get_timer_cycles()`, or raw TSC conversion as an alternate runtime mode. The
    Backend never silently changes clocks; Decision 64 defines source-failure handling. Any future hot-path optimization
    must preserve BOOTTIME semantics and be justified by measurement. See ADR-0064.
60. Each DPDK packet that reaches a Cache/Pending time-dependent decision reads `CLOCK_BOOTTIME` at that packet's
    processing point. Cache Hit expiry/aging, Query Pending refresh, and Response timeout/observation therefore never
    reuse a burst- or quantum-start timestamp. Each 32-Entry Cache or Pending cleanup batch reads one fresh time and
    applies it to that bounded batch. This prevents scheduler preemption or suspend during a burst from making later
    packets use stale time while avoiding a clock read per cleanup Entry. `PERF-9B-6` may compare burst sampling only if
    it preserves expiration correctness under injected long pauses and meets a predeclared performance threshold. See
    ADR-0065.
61. A generated DPDK Cache Hit frame exactly follows the eBPF normalized packet contract. It swaps Query Ethernet
    source/destination addresses and emits IPv4 EtherType; swaps IPv4 and UDP endpoints; emits IPv4 version/IHL 4/5,
    TOS zero, exact total length, ID zero, DF set, fragment offset zero, TTL 64, UDP protocol, and a software-computed
    IPv4 checksum; emits exact UDP length and zero IPv4 UDP checksum; and applies the shared DNS Transaction ID,
    Question, and TTL-aging semantics. Before client TX, the Path clears inherited RX/TX offload flags, packet type,
    VLAN tags, RSS/hash data, and TX-offload length metadata while preserving only mbuf allocator/ownership fields and
    the exact single-segment data layout. Module 9B requests no checksum or other TX offload and has no PMD-dependent
    output variant. See ADR-0066.
62. DPDK startup initializes `DpdkEal`, configures the two `DpdkPort` objects, and creates their shared `DpdkPacketPool`
    before the concrete Cache Store and Pending table because both own `rte_hash` allocations that require a live EAL.
    It then constructs `DnsPolicy`, the two Packet Path tasks, both maintenance tasks, and their private scheduler before
    `start()` succeeds; no packet poll occurs against partial composition. Normal and partial-start cleanup first
    destroys the scheduler/tasks and Policy, then Pending and Cache hash owners, then closes Service/Client, the shared
    pool, and EAL. No Store/Pending hash is placed inside a native resource object merely to make cleanup ordering
    implicit. See ADR-0067 and ADR-0071.
63. `DpdkCacheStore` owns one mutex that serializes its single `store()` caller with its potentially concurrent
    `cleanup()` caller, as required by the shared Cache Store contract and conformance suite. The direct concrete
    `lookup()` used by Client Packet Path does not acquire this mutex and is not promised concurrent execution with
    Store mutation in Module 9; production lookup, Fill, and cleanup remain serialized by the sole cooperative lcore.
    The mutex is therefore uncontended in production and never enters the per-packet Hit path, while standalone Store
    conformance tests may exercise the required writer/cleanup concurrency. Pending has no analogous shared interface
    requirement and remains mutex-free. See ADR-0068.
64. A DPDK BOOTTIME read failure is local Fail-open degradation, never `PollFailed`. On the Client Packet Path, the
    packet performs no Cache lookup or Pending mutation and forwards unchanged to service. On the Service Packet Path,
    it performs no Pending claim, Policy classification, or Cache Fill and forwards unchanged to client. A maintenance
    task that cannot obtain its batch timestamp performs no inspection or deletion, leaves its current deadline,
    cursor, remaining count, and Entry ownership unchanged, and retries time acquisition in the next Poll Quantum.
    No path reuses stale time or selects an alternate clock. Each of the three failure categories emits at most one
    `spdlog::warn()` per Backend lifetime; Module 10 may replace this minimal suppression with unified Diagnostics.
    See ADR-0069.
65. Module 9A accepts native DPDK EAL arguments only after the Shinku CLI `--` separator and passes them unchanged to
    `rte_eal_init()`, apart from prepending the required program name. Shinku generates no lcore, memory, PCI, vdev,
    process-type, file-prefix, or Telemetry option, and an empty EAL argument list is valid. TOML keeps only
    `backend = "dpdk"`; it has no effective `[dpdk]` fields in this MVP. Obsolete `[dpdk]` tables are temporarily ignored
    with a Config Loader TODO for the final migration policy. This supersedes decisions 4, 7, 13, 14, 30, 31, 33-36
    where they require typed Device Sources or Shinku-generated EAL arguments. See ADR-0070.
66. The MVP requires exactly two available ethdev ports after EAL initialization and fixes Port 0 as client and Port 1
    as service. The launch command owns the native EAL options that establish this exact device set and enumeration
    order. Zero, one, or more than two available ports is `StartFailed`; there is no TOML or Shinku-side port override.
    See ADR-0070.
67. Superseded by decision 68. The previous production Session boundary and broad `DpdkNativeOperations` function-pointer
    table are both removed; the production adapter is covered by the real EAL/net_ring smoke.
68. `DpdkEal`, `DpdkPacketPool`, and `DpdkPort` are separate narrow object-oriented resource boundaries. Unit tests fake
    those objects independently; no per-function DPDK operation table or mixed Session façade is introduced. Non-null
    internal dependencies use ordinary C++ references, nullable test-only cache context uses a raw pointer, and DPDK's
    C handles remain behind the production resource adapters. See ADR-0071.
