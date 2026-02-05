## Project Overview: eBPF Kernel-Level DNS Cache System Based on `bpf_arena`

### 1. Core Design Philosophy & Architectural Advantages

This project aims to build a high-performance, low-latency DNS caching system. It leverages the modern eBPF tech stack (Linux 5.8+ Ring Buffer, Linux 6.9+ BPF Arena) to completely reconstruct traditional kernel-level caching solutions.

* **Fast Path (XDP):** Intercepts and responds to DNS queries directly at the network driver layer (Ingress). By bypassing the entire kernel network stack, it achieves nanosecond-level query response times.
* **Slow Path (TC + User Space):** Captures upstream DNS responses at the protocol stack exit (Egress). Complex protocol parsing and memory management are handled in user space to bypass the strict eBPF verifier constraints (e.g., handling DNS compression pointers and complex loops).
* **Zero-Copy & No-Fragmentation (Arena):** Introduces `bpf_arena` to replace traditional `BPF_MAP_TYPE_ARRAY` segmented storage. By sharing memory between the kernel and user space, it enables contiguous storage of variable-length DNS response data and direct pointer access, eliminating memory fragmentation and significantly simplifying code logic.

---

### 2. System Components & Tech Stack

| Component | Location | Core Technology | Primary Responsibility |
| --- | --- | --- | --- |
| **Ingress Processor** | Kernel (XDP) | XDP_TX, `bpf_arena` | **"Search & Send"**: Intercept requests, look up cache, atomically replace IDs, and reflect responses. |
| **Egress Capturer** | Kernel (TC) | `sk_buff`, Ring Buffer | **"Capture & Transport"**: Capture upstream responses and copy Raw Packets to the Ring Buffer. |
| **Control Plane Service** | User Space | libbpf, `bpf_arena` | **"Parse & Store"**: Consume Ring Buffer, parse DNS protocols, manage Arena memory allocation, and update Hash Maps. |
| **Storage Backend** | Shared Memory | `BPF_MAP_TYPE_ARENA` | Stores complete, serialized DNS response packets (Header + Question + Answer). |
| **Index Backend** | Kernel Map | `BPF_MAP_TYPE_HASH` | Key: Domain Hash + QTYPE; Value: Pointer to Arena memory + Metadata (TTL). |

---

### 3. Detailed Workflow

#### Scenario A: Cache Hit (Fast Path - XDP)

The most frequent execution path, optimized for extreme performance.

1. **Packet Interception (`xdp_rx_filter`):** Filters for UDP traffic on destination port 53.
2. **Parsing & Hashing:** Extracts the Transaction ID, QNAME (Domain), and QTYPE. Computes a hash (e.g., FNV-1a).
3. **Lookup:** Queries the `BPF_MAP_TYPE_HASH`. If it misses, it returns `XDP_PASS`. If it hits, it retrieves the Arena pointer and TTL.
4. **Validity Check:** Compares `bpf_ktime_get_ns()` with the cached expiration time.
5. **Response Construction & Hot Patching:** * **Pointer Dereference:** Uses `bpf_arena` to directly read the cached response from shared memory.
* **ID Replacement:** Overwrites the cached Transaction ID with the current request's ID.
* **Header Swapping:** Swaps Source/Destination MACs, IPs, and Ports.
* **Checksum Correction:** Recomputes IP and UDP checksums using incremental update algorithms.


6. **Transmission:** Calls `XDP_TX` to send the modified packet directly back out the same interface.

#### Scenario B: Cache Miss & Filling (Slow Path - TC + User)

The path for establishing cache; millisecond latency is acceptable.

1. **Upstream Query:** XDP-passed requests are handled by the kernel stack and sent to an upstream DNS server.
2. **Response Capture (`tc_tx_filter`):** A TC program on the Egress hook filters UDP packets from source port 53.
3. **Data Transfer:** Uses `bpf_skb_load_bytes` to copy the Raw Packet into a Ring Buffer, waking the user-space service.
4. **User-Space Processing:**
* **Parse & Normalize:** Uses full-featured DNS libraries (e.g., `miekg/dns`) to handle compression pointers and CNAMEs. Serializes the response into a self-contained format.
* **Arena Allocation:** Allocates contiguous space in the Arena memory pool via a user-space allocator.
* **Update Map:** Writes the serialized data to the Arena and updates the `BPF_MAP_TYPE_HASH` with the pointer, TTL, and length.



---

### 4. Key Technical Challenges & Solutions

| Challenge | Risk | Solution (Architectural Decision) |
| --- | --- | --- |
| **Transaction ID Mismatch** | Direct replay of cached data leads to ID mismatch, causing clients to silently drop the packet. | **XDP Hot Patching:** Extract the request ID and overwrite the ID field in the cached response buffer before sending, then fix the checksum. |
| **Compression Pointer Invalidity** | Raw packet copies may contain offsets (0xC0xx) pointing to memory outside the stored buffer. | **User-Space Normalization:** The control plane re-serializes the DNS packet into a "flattened" or self-contained format, removing external references. |
| **Arena Memory Management** | `bpf_arena` does not provide `malloc`/`free`; the kernel cannot dynamically allocate. | **User-Space Allocator:** Implement a Slab/FreeList allocator in user space. The user-space service manages reclamation during TTL expiration or LRU eviction. |
| **Concurrency/Race Conditions** | XDP might read partial data while the user-space service is writing to the Arena. | **Atomic Update Strategy:** 1. Write complete data to a *new* Arena address. 2. Update the Hash Map pointer in one atomic step. XDP sees either the old or new data, never a "half-written" state. |
| **TTL Expiration Handling** | Serving stale DNS data causes business logic issues (e.g., delayed IP migration). | **Double Check:** 1. User-space periodically scans and cleans (active). 2. XDP checks the `expire_timestamp` in the Value struct during every lookup (passive). |

