### Phase 1: Infrastructure Enhancement (Current)

* [x] **Fix** DNS Label parsing logic in `hash.h`.
* [x] **Resolve** misaligned memory access for `qtype/qclass` in `cache.bpf.c`.
* [x] **(Optional) Add** VLAN (0x8100) parsing support in `parser.h` to ensure compatibility with K8s/Minikube environments.

### Phase 2: Control Plane & Data Channel (RingBuf)

* [ ] **Implement** a new `SEC("tc")` program in `cache.bpf.c`:
    * Attach to the **egress** hook.
    * Capture UDP packets where `src_port == 53`.
    * Submit the raw packet data to a **Ring Buffer**.


* [ ] **Develop** Ring Buffer consumer logic in `main.c`:
    * Parse DNS Responses.
    * Extract **TTL** and **Answer** records.



### Phase 3: BPF Arena Integration (Core Feature)

* [ ] **Define** the Arena Map (`BPF_MAP_TYPE_ARENA`).
* [ ] **Implement** a lightweight memory allocator (**Slab allocator**) in `user/main.c` to manage Arena memory.
* [ ] **Write** parsed DNS responses into the Arena from user-space.
* [ ] **Update** `entry_map` (Hash Map) such that values store pointers to the allocated Arena memory.

### Phase 4: XDP Hot-Patching (Completion)

* [ ] **Implement** table lookups (`bpf_map_lookup_elem`) within the `xdp_ingress` program.
* [ ] **Critical:** Implement **pointer dereferencing** for Arena memory access.
* [ ] **Critical:** Implement **Hot-Patching** for DNS Transaction IDs.
* [ ] **Critical:** Implement **incremental checksum updates** (IP & UDP) for modified packets.
* [ ] **Execute** `XDP_TX` for accelerated packet redirection.

---

**Would you like me to help you draft the C code for the Slab allocator in Phase 3, or perhaps the incremental checksum logic for Phase 4?**
