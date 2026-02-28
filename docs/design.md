# DNS Cache System Design Document

## 1. Overview

### System Purpose
The DNS Cache is a high-performance, transparent DNS caching proxy. It leverages eBPF XDP (Express Data Path) to achieve line-rate cache hits by intercepting and responding to DNS queries directly at the network driver level. By handling the "hot path"—consisting of cache lookup and response generation—entirely within the kernel's XDP hook, the system bypasses the heavy overhead of the Linux networking stack for cached entries.

### Design Philosophy
The core design philosophy is to minimize complexity in the kernel while maximizing performance. The system splits responsibilities between the XDP layer and a userspace control plane:
- **XDP Layer (Hot Path)**: Handles packet parsing, cache lookup, and response transmission. It is optimized for speed and uses a flat memory model for zero-copy access to cached data.
- **Userspace (Cold Path)**: Manages complex logic such as full DNS packet validation, compression pointer flattening, TTL management, and cache population. This keeps the BPF programs lean and verifier-friendly.

---

## 2. Architecture

The system follows a three-layer architecture: the XDP layer for ingress queries, the TC layer for egress response capture, and the userspace daemon for cache management.

### Layer 1: XDP Ingress (xdp_rx)
The XDP program is attached to the ingress hook of the DNS-facing interface. Its execution flow is as follows:
1. **Packet Parsing**: Iteratively parses Ethernet, VLAN, IPv4, and UDP headers.
2. **DNS Validation**: Ensures the packet is a DNS query (UDP port 53, QR=0).
3. **Hashing**: Computes an FNV-1a hash of the QNAME (query name).
4. **Cache Lookup**: Uses the hash to look up a entry in `cache_map`.
5. **Cache Hit**: If a valid, non-expired entry is found:
   - Retrieves the response payload from the BPF arena.
   - Patches the DNS Transaction ID (TxID) from the query into the cached response.
   - Swaps Layer 2 (MAC), Layer 3 (IP), and Layer 4 (Port) source/destination headers.
   - Updates the IP total length and recalculates the IP checksum incrementally.
   - Zeros the UDP checksum (valid for IPv4).
   - Returns `XDP_TX` to reflect the packet back out the same interface.
6. **Cache Miss**: Returns `XDP_PASS`, allowing the kernel to process the query normally.

### Layer 2: TC Egress (tc_tx)
The Traffic Control (TC) program is attached to the egress hook of the interface. It monitors outgoing DNS responses (UDP source port 53).
1. **Capture**: Extracts the DNS payload using `bpf_skb_load_bytes`.
2. **Transfer**: Sends the packet data to userspace via the `rb_pkt` ring buffer for processing and potential caching.

### Layer 3: Userspace Daemon
The userspace daemon runs an event loop polling two ring buffers: `rb_pkt` (captured responses) and `rb_log` (debug logs).
- **Processing**: When a response is received, userspace validates the packet (RCODE=0, QR=1, etc.).
- **Normalization**: It flattens any DNS compression pointers to create a self-contained, uncompressed wire-format packet.
- **Storage**: The flattened packet is written directly into the mmap'd BPF arena, and the `cache_map` is updated with the new hash and metadata.

### Data Flow Diagram

```text
      QUERY (Ingress)             RESPONSE (Egress)
            |                             ^
            v                             |
    +-------+-------+             +-------+-------+
    |    XDP_RX     |             |     TC_TX     |
    | (BPF Kernel)  |             | (BPF Kernel)  |
    +-------+-------+             +-------+-------+
            |                             |
      HIT?  |  MISS?                      | Capture
      [TX]<-+->[PASS]                     |
                 |                        v
                 |                +-------+-------+
                 |                |    RINGBUF    |
                 |                +-------+-------+
                 |                        |
                 |                +-------+-------+
                 +--------------->|   USERSPACE   |
                   Normal Stack   |   (Control)   |
                                  +-------+-------+
                                          |
                                  +-------+-------+
                                  |   BPF ARENA   |
                                  | (Shared Mem)  |
                                  +---------------+
```

---

## 3. Data Structures

The system uses specific structures to maintain state and communicate between layers.

### struct cache_key (12 bytes)
Used as the key for the `cache_map` hash map.
- `name_hash`: 32-bit FNV-1a hash of the normalized QNAME.
- `qtype`: 16-bit query type (e.g., A, AAAA).
- `qclass`: 16-bit query class (typically IN).
- `_pad`: 32-bit padding for alignment.

### struct cache_value (16 bytes)
The value stored in `cache_map`.
- `arena_idx`: Index into the BPF arena where the payload is stored.
- `pkt_len`: Total length of the cached DNS packet.
- `scope`: ECS scope prefix (used for subnet-specific logic).
- `_pad`: 8-bit padding.
- `expire_ts`: Expiration timestamp in nanoseconds (ktime_ns).

### struct cache_entry (512 bytes)
Represents a single entry in the arena. It is a flat buffer containing the full DNS response packet, including headers and the answer section, but with authority and additional sections stripped.

### struct dns_event (Variable)
Used to pass egress packets from TC to userspace via ring buffer.
- `timestamp`: Capture time.
- `len`: Length of the payload.
- `payload[]`: Raw DNS packet bytes.

### struct dns_hdr (12 bytes)
Standard DNS header structure with packed attributes for transaction ID, flags, and record counts.

---

## 4. BPF Arena Memory Model

The system utilizes the BPF Arena, a relatively new feature that provides a shared memory region between BPF programs and userspace.

### Why Arena?
- **Efficiency**: Arena allows direct pointer access. Unlike standard BPF maps, XDP can read the payload via a pointer without the overhead of `bpf_map_lookup_elem`.
- **Zero-Copy**: The arena is mmap'd into the userspace process. Userspace writes the flattened DNS packets directly into this memory, and XDP reads them instantly.
- **Compiler Support**: The `__arena` annotation allows the compiler to generate specialized code for address space casting.

### Allocation
A simple bump allocator is used. Userspace maintains `next_entry_idx` and increments it for every new cache entry. The default size is 2112 pages (approx. 8.25MB), accommodating 16,384 entries of 512 bytes each.

### Address Space Cast
To support various kernel versions and toolchains, the arena uses the `#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)` macro. If the feature is missing, it falls back to the `.addr_space.1` section to ensure the verifier correctly identifies arena pointers.

---

## 5. Hashing Strategy

The system uses the FNV-1a (Fowler-Noll-Vo) 32-bit hash algorithm for its simplicity and efficiency in BPF.

- **Normalization**: DNS is case-insensitive. Before hashing, both userspace and BPF normalize all uppercase characters in the QNAME to lowercase.
- **Wire Format**: The hash is computed on the wire-format QNAME (e.g., `\03www\06google\03com\00`). Length bytes are included in the hash to prevent collisions between labels (e.g., `3abc` vs `1a2bc`).
- **BPF Implementation**: The BPF side uses a linear byte-by-byte loop. This is verifier-friendly as it has a fixed maximum bound of 255 iterations (the maximum length of a DNS name).
- **Userspace Implementation**: Userspace follows compression pointers while hashing to ensure the hash matches the uncompressed version used in the cache.

---

## 6. DNS Response Processing (Userspace)

Userspace performs heavy lifting to ensure that only high-quality, valid responses enter the cache.

### Validation Requirements
A response must meet these criteria:
1. `QR=1`: Must be a response.
2. `TC=0`: Must not be truncated.
3. `RCODE=0`: Status must be NOERROR.
4. `QDCOUNT=1`: Exactly one question.
5. `ANCOUNT>0`: At least one answer record.
6. Answer types must be restricted to A or AAAA.
7. TTL must be greater than zero.

### Compression Pointer Flattening
DNS responses often use compression pointers (0xC0xx) to save space by pointing back to previously occurring names. XDP cannot easily follow these pointers because it would require non-linear packet access and potentially complex state tracking.
Userspace "flattens" these names by resolving all pointers and writing the full, uncompressed labels into the arena. This allows XDP to perform a simple, contiguous memory copy when generating a cache hit response.

### Section Stripping
To conserve space and simplify XDP logic, the Authority and Additional sections are stripped from the cached packet. The `nscount` and `arcount` fields in the DNS header are reset to 0 in the cached version.

---

## 7. ECS (EDNS Client Subnet) Handling

EDNS Client Subnet (ECS) allows recursive resolvers to pass client network information to authoritative servers. This presents a caching challenge, as different subnets might receive different answers for the same query.

### Strategy: Scope-Zero Only
The system adopts a conservative "scope-zero only" caching policy:
- If a response contains an ECS option:
    - If `scope_prefix == 0`, the answer is globally valid and is cached.
    - If `scope_prefix > 0`, the answer is subnet-specific. To avoid serving incorrect data to other clients, the system does not cache these responses.
- If no ECS option is present, the response is treated as global and is cached.

This approach ensures correctness while still providing significant performance gains for the majority of global DNS traffic.

---

## 8. XDP Hot Path Optimizations

The XDP hot path is heavily optimized to minimize CPU cycles per packet.

- **Wide Copying**: Instead of byte-by-byte copying, the system uses 8-byte wide `__u64` reads and writes to move data from the arena to the packet buffer. This reduces loop iterations significantly. Any remaining bytes (0-7) are handled by a fully unrolled loop.
- **Incremental Checksums**: Recalculating an IP checksum from scratch is expensive. The system uses RFC 1624 incremental updates. Since only the `tot_len` and addresses change (swapped), it uses `csum_replace2` for a fast update.
- **UDP Checksum Offload**: For IPv4, a UDP checksum of zero is technically valid (RFC 768). By zeroing the checksum, the system avoids the most computationally expensive part of packet construction.
- **Verifier Hints**: After calling `bpf_xdp_adjust_tail()`, packet pointers must be re-derived. The system uses bitwise AND masks (e.g., `& 0x1ff`) to narrow scalar offsets. Unlike conditional checks, AND masks satisfy the verifier's requirements for both 32-bit and 64-bit bounds, which is essential for pointer arithmetic in the arena.
- **Conditional Logging**: Production builds disable the `rb_log` ring buffer via the `ENABLE_BPF_LOG` macro. This removes the overhead of ring buffer reservations and commits, which can be substantial at high packet rates.

---

## 9. TC Egress Capture

The TC program uses `bpf_skb_load_bytes` rather than direct packet access. This is because the `__sk_buff` context does not always provide a contiguous view of packet data in the same way the XDP `xdp_md` context does.
The capture logic derives the DNS payload length from the IP header `tot_len` rather than `skb->len`. This ensures that any Ethernet padding or trailers are excluded from the captured data. The payload is capped at 512 bytes to match the standard DNS UDP limit.

---

## 10. Build System

The project uses the Meson build system, providing a modern and efficient workflow for C and BPF compilation.

- **BPF Integration**: Meson handles the compilation of BPF source files using Clang, targeting the BPF architecture.
- **Logging Control**: The `bpf_log` option in `meson_options.txt` toggles the `ENABLE_BPF_LOG` definition. This allows users to easily switch between a verbose debug build and a high-performance production build.
- **Dependency Management**: The `c-ares` library is managed via Meson subprojects, ensuring it is fetched and built automatically if not found on the system.
- **Artifacts**: The build produces the `dns-cache` userspace binary and the `xdp_pass.bpf.o` helper program used for veth peer configurations in test environments.

---

## 11. Limitations and Future Work

While highly performant, the current implementation has several areas for improvement.

- **Arena Management**: The current bump allocator is "leaky"—it never frees entries. Over a long period, the arena will fill up. A future improvement would be a ring buffer allocator or a free-list mechanism.
- **Protocol Support**: Currently, only IPv4 is supported in the XDP path. Extending this to IPv6 would require additional parsing logic and checksum handling.
- **Record Types**: The cache is limited to A and AAAA records. Responses containing CNAME, MX, or TXT records are currently passed through without caching.
- **Negative Caching**: The system does not cache NXDOMAIN or SERVFAIL responses. Implementing this would reduce load on upstream resolvers for non-existent domains.
- **Cache Eviction**: Expired entries are not proactively removed from `cache_map`. They remain until they are overwritten by a hash collision or the map is cleared.
- **Hardware Acceleration**: The system is currently tested using Generic XDP on veth interfaces (SKB mode). Running on a native XDP-supported NIC would provide even greater performance.
