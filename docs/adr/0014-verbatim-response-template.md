# Verbatim Response Template

A Cache Entry stores the upstream DNS message byte for byte, from the DNS header to the end of the message, and a Cache Hit rewrites only the Transaction ID, the Question Section bytes, and every RR TTL. No section is stripped, no name is decompressed, no header bit is normalized — including `AA`, which conventional caches clear. Shinku is a Transparent Cache: the client believes it is talking to the DNS Service Endpoint directly, so anything that makes a Cache Hit distinguishable from a forwarded Response is a defect rather than good citizenship.

**Considered Options**

- Keep the legacy behavior of rebuilding a flattened message with only the Answer Section.
- Store verbatim but clear `AA` on a hit, matching unbound and dnsmasq.
- Store verbatim and rebind only ID, question bytes, and TTLs.

**Consequences**

The legacy rebuild path disappears, including `flatten_name` and its thread-local flat buffer. Negative responses keep their Authority Section SOA, so a downstream forwarder can negative-cache consistently instead of only on the requests that happened to miss. Compression pointers stay valid because Cache Key identity fixes the question wire length, and a pointer into the Question Section resolves against the current querier's own QNAME case, which delivers case echo for free.

The TTL patch plan must therefore cover every RR in every section, not just the Answer Section. A negative response carries its only TTL in the Authority SOA, so an Answer-only plan would replay a fixed TTL and re-arm every downstream cache for a full TTL on each hit — worse than dropping the section, because it actively emits false information rather than merely omitting information.
