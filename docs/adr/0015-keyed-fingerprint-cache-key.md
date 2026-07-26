# Keyed Fingerprint Cache Key with Plaintext Namespace

The physical eBPF cache key is a plaintext `CacheNamespace` — the Query destination IPv4 address and UDP port — followed by a 128-bit keyed fingerprint of the canonical question name, type, and class. The fingerprint must be a keyed PRF such as SipHash with a secret generated randomly per process; an unkeyed 128-bit hash would let anyone who can send Queries through the Cache Point construct a colliding pair offline and use the cache as a poisoning primitive, which no output width prevents.

**Considered Options**

- Keep the legacy 32-bit FNV name hash.
- Use the complete logical key, roughly 268 bytes, as the BPF map key for exact comparison.
- Hash the whole logical key, namespace included, into one 128-bit fingerprint.
- Plaintext namespace plus a keyed 128-bit fingerprint of the rest.

**Consequences**

The legacy 32-bit key is not a representation detail but a defect: with question type and class constant under the MVP Query Profile the effective key is 32 bits, which by the birthday bound gives roughly a 3 percent chance of a colliding pair at the current 16384-entry map and roughly 50 percent at 65536 entries. A collision does not produce a miss; it makes XDP serve one name's answer for a different name, repeatably, and downstream caches propagate it.

Keeping the namespace in plaintext makes cross-namespace isolation exact rather than probabilistic, leaves the owning endpoint readable in a map dump, and keeps residual collision risk confined within a single namespace at roughly 2^-97, which is below hardware error rates and not worth engineering against.

The fingerprint gets exactly one implementation, a shared `static __always_inline` header compiled into both the BPF object and the Host Runtime in the manner of `src/core/hash.h`, and the key struct is defined once in the shared `types.h` with explicit padding and mandatory zero-initialization. Divergent implementations and uninitialized padding bytes produce the same symptom — a permanent zero hit rate with no error reported anywhere — which is why both are covered by one focused test.

Module 8D writes the secret into `.rodata` between skeleton open and load, which is the single place where it extends the Module 8A Session signature. BPF maps are not pinned today; pinning them later would strand every entry fingerprinted under a previous secret.
