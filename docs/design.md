
# Design Specification: Industrial-Grade eBPF DNS Cache

## 1. Core Design Philosophy

This project aims to build a high-performance, low-latency, and **strictly correct** DNS caching system. It utilizes the modern eBPF tech stack (Linux 5.8+ Ring Buffer, Linux 6.9+ BPF Arena) to reconstruct traditional kernel-level caching solutions.

* **Fast Path (XDP Ingress):** "Search & Send". Intercepts queries at the driver layer. It performs O(1) lookups in `bpf_arena` and reflects responses immediately, bypassing the kernel stack.
* **Slow Path (TC Egress + User Space):** "Capture, Sanitize, & Store". Captures upstream responses, performs protocol normalization (flattening), enforces safety policies (ECS), and manages memory.
* **Zero-Copy Storage (Arena):** Uses `bpf_arena` to store **linearized, self-contained** DNS packets. This eliminates the complexity of handling compression pointers in the kernel verifier.

---

## 2. Architecture & Components

| Component | Location | Core Technology | Primary Responsibility |
| --- | --- | --- | --- |
| **Ingress Filter** | Kernel (XDP) | `XDP_TX`, `bpf_arena` | **Fast Path**: Look up `Cache Key` (Hash+Type), atomically replace Transaction ID, hot-patch MAC/IP, and reflect packet. |
| **Egress Capturer** | Kernel (TC) | `sk_buff`, RingBuf | **Capture**: Filters UDP/53 responses. Checks basic validity. Copies **Raw Data** (Header + Payload) to Ring Buffer. |
| **Control Plane** | User Space | libbpf, `bpf_arena` | **Normalization Engine**: Consumes RingBuf. Flattens compression pointers. Filters ECS (EDNS). Allocates Arena memory. Updates Hash Map. |
| **Index Backend** | Kernel Map | `BPF_MAP_TYPE_HASH` | **Metadata**: Key = `Hash + QType + QClass`. Value = Pointer to Arena data + Expiry Timestamp. |
| **Storage Backend** | Shared Mem | `BPF_MAP_TYPE_ARENA` | **Payload**: Stores the **Normalized (Flattened)** DNS Packet. |

---

## 3. Detailed Data Workflow

### 3.1. Fast Path: Cache Hit (XDP)

*No changes from original design. Focus is on read-only performance.*

1. **Parse:** Extract ID, QNAME (Hash), QTYPE.
2. **Lookup:** Check Hash Map. If miss -> `XDP_PASS`.
3. **Validate:** Check `bpf_ktime_get_ns() < entry->expire_ts`.
4. **Reflect:** Direct `memcpy` from Arena to packet buffer (linear copy, no pointer chasing). Patch ID and Checksums. `XDP_TX`.

### 3.2. Slow Path: Cache Fill (User-Space Normalization)

This is the critical "Industrial-Grade" logic ensuring data safety and correctness.

#### Step 1: Ingestion & Validation

Upon receiving a raw packet from the Ring Buffer:

* **Protocol Check:** Ensure packet is a Response (`QR=1`) and standard Query (`Opcode=0`).
* **Truncation Check:** Check the **TC Bit** (`Flags & 0x0200`).
* *Decision:* If `TC=1`, **DROP**. Do not cache truncated UDP packets. Clients must retry via TCP (which we do not cache in V1).


* **RCODE Check:** Only cache `RCODE=0` (NOERROR).
* **QDCOUNT Check:** Ensure `QDCOUNT=1` (standard single-question query).

#### Step 2: ECS Policy Enforcement (Scope-Zero Strategy)

To prevent "Cache Poisoning" where a subnet-specific IP (e.g., intended for Beijing) is served to a global user (e.g., New York).

* **Scan Additional Section:** Iterate through OPT RRs (Type 41).
* **Check ECS Option (Code 8):**
* If **Scope Mask > 0** (Specific): **IGNORE PACKET**. Do not cache. This response is tailored to a specific client subnet.
* If **Scope Mask == 0** (Global) OR **No ECS present**: **PROCEED**. This is a generic response safe for all users.



#### Step 3: Protocol Normalization (Flattening)

The XDP verifier struggles with loops and non-linear memory access (compression pointers `0xC0xx`). The User Space Control Plane must "flatten" the packet into a linear format.

1. **New Buffer:** Allocate a flat buffer (e.g., `flat_buf[1500]`).
2. **Header:** Copy standard header. **Force `ARCOUNT=0**` (Strip OPT/ECS records to ensure the cached response is generic and protocol-compliant for replay).
3. **Question Section:** Read QNAME from raw packet (handling pointers), write full labels to `flat_buf`. Copy QTYPE/QCLASS.
4. **Answer/Authority Sections:**
* Iterate every Record.
* **Expand Name:** Resolve compression pointers in the `NAME` field to full labels.
* **Expand RDATA:** If the Record Type is `CNAME`, `NS`, or `PTR`, resolve compression pointers *inside* the RDATA.
* **Copy Data:** Write `TYPE`, `CLASS`, `TTL`, `RDLENGTH` (re-calculated), and linear `RDATA` to `flat_buf`.



#### Step 4: Storage & Indexing

1. **Arena Allocation:** Allocate `sizeof(entry) + flat_len` from the user-space managed slab allocator.
2. **Write:** `memcpy` the `flat_buf` into the Arena memory.
3. **Commit:** Update the `BPF_MAP_TYPE_HASH` with the Arena offset and TTL.

---

## 4. Key Architectural Decisions & Trade-offs

| Challenge | Architectural Decision | Justification (Industrial Grade) |
| --- | --- | --- |
| **Verifier Complexity (Loops)** | **User-Space Normalization** | Instead of storing raw packets with compression pointers (which requires complex unpacking in XDP), we store **flattened, linear packets**. XDP simply performs a `memcpy`, satisfying the verifier and maximizing performance. |
| **Cache Poisoning (ECS)** | **Scope-Zero Strategy** | We strictly **only cache global responses** (ECS Scope=0). Subnet-specific responses are passed through. This guarantees correctness over hit-rate. Serving a Beijing IP to a New York user is a fatal error; missing a cache is acceptable. |
| **Privacy & Protocol Safety** | **Strip Additional Section** | We strip the `OPT` RR (ECS data) from the cached payload. This ensures the replayed packet does not contain stale or irrelevant client subnet data, and prevents `UDP Payload Size` negotiation mismatches during replay. |
| **Truncated Packets (TC)** | **Drop / No-Cache** | Packets with `TC=1` are incomplete. Caching them would serve broken data. We rely on the client's standard retry mechanism (fallback to TCP) and do not cache TCP traffic in V1. |
| **Memory Fragmentation** | **User-Space Allocator** | Since `bpf_arena` is a raw memory region, the Control Plane implements a Slab/FreeList allocator to manage variable-length DNS entries efficiently without kernel overhead. |

---

## 5. Summary of "Industrial-Grade" Features

1. **Safety First:** The system explicitly filters out risky packets (Truncated, Non-Zero Scope ECS, Multi-Question).
2. **Verifier Friendly:** By moving the complexity of DNS parsing (de-compression) to user space, the kernel program remains extremely simple and stable.
3. **Atomic Updates:** The "Prepare in Arena -> Switch Pointer in Map" flow ensures XDP never sees partially written data.
4. **Correctness:** By adhering to the **Scope-Zero** strategy, the cache guarantees that cached data is universally valid, avoiding geo-location routing errors common in naive DNS caches.
