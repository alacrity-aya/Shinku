# Correlated Verbatim Packet Cache Policy

Module 8C is a Correlated Verbatim Packet Cache Policy rather than a partial recursive resolver or RRset cache. After a Response has passed Query Correlation, Shinku verifies only the invariants needed to store and replay the complete message safely: bounded wire traversal, Question-derived identity, exact message boundaries, every retained RR TTL offset, negative lifetime, and the active Cacheable Response Profile. It trusts the DNS Service Endpoint's answer semantics and therefore does not resolve CNAME chains, require a terminal A record, reject unrelated-but-structurally-valid Answer records, or whitelist RR types solely because 8C does not interpret them.

**Considered Options**

- Validate complete Answer semantics, including a unique CNAME chain, terminal A ownership, and SOA ancestry.
- Admit correlated, structurally safe responses and retain the upstream message verbatim.
- Treat the Response as opaque bytes and cache every correlated packet.

**Consequences**

The current upstream Response remains Fail-open and is forwarded regardless of Cache Admission. A structurally malformed message or one whose TTLs, identity, lifetime, or boundaries cannot be handled safely becomes a Bypass; a structurally valid but semantically unusual answer may become a Cache Candidate and is replayed without changing its meaning. This keeps Shinku responsible for cache correctness while leaving recursive resolution, DNSSEC, authority selection, and answer correctness with the configured DNS Service Endpoint.

The parser still traverses every Header-declared RR owner and generic RR boundary and records every TTL field. It interprets the Question to construct cache identity and records whether the Authority Section contains an `IN/SOA`, but it does not decode CNAME targets, parse SOA RDATA, or build Answer relationships. Following dnsdist's packet-cache semantics, Shinku trusts the upstream DNS Service Endpoint to have emitted the effective RFC 2308 negative TTL in the SOA RR TTL field. Unlike dnsdist's best-effort walker, Shinku requires complete traversal of every declared RR because its XDP Cache Hit Path consumes a precomputed complete TTL patch plan and cannot safely reparse or partially age a Response. Bytes remaining after that traversal are retained as an opaque suffix within the validated UDP payload; they are replayed verbatim and are neither interpreted as RRs nor added to the TTL patch plan.

Wire TTLs follow RFC 2181's 31-bit maximum: a received TTL with its high bit set is interpreted as zero, not masked or clamped. Because a verbatim Response Template cannot expire its RRsets independently, any normalized zero TTL makes the whole Response a `ZeroLifetime` Bypass while the current upstream Response continues through Fail-open forwarding.

Each `DnsPolicy` instance owns mutable TTL-offset scratch and is therefore single-caller and non-thread-safe. A successful `CacheCandidate` borrows that scratch and the packet-event response memory, so Backend composition must consume it synchronously through `CacheStore::store()` before either the packet callback returns or the same Policy classifies another Response. Concurrent workers own separate Policy instances rather than contending on a mutex. A future asynchronous Cache Fill Path must first copy both borrowed ranges into bounded owned work; exhaustion abandons only the fill attempt.
