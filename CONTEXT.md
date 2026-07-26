# Shinku Refactor Context

This glossary defines project language for the C++/DPDK refactor. It intentionally avoids module-level implementation details.

## Language

### System Shape

**Cache Engine**:
A pluggable runtime that receives DNS packets, checks the cache, forwards misses, and emits cache events.
_Avoid_: Loader, dataplane module

**Backend**:
A concrete Cache Engine implementation for one packet-processing environment.
_Avoid_: Mode, driver

**eBPF Backend**:
The runnable Cache Engine that uses eBPF programs for packet handling and must remain operational during the refactor.
_Avoid_: Legacy backend

**DPDK Backend**:
The Cache Engine that uses DPDK packet I/O and userspace packet buffers.
_Avoid_: DPDK mode

**Backend-neutral**:
A rule or type that applies equally to all Backends instead of belonging to eBPF or DPDK specifically.
_Avoid_: Shared by accident

**Host Runtime**:
The non-eBPF process code that runs in userspace and owns process lifecycle, backends, cache policy, and control-plane work.
_Avoid_: Userspace code

**Control Plane**:
The management path that owns configuration, lifecycle, response validation, cache insertion, eviction, and shutdown.
_Avoid_: CLI, userspace loop

**Data Plane**:
The packet path that parses DNS queries, performs cache lookup, forwards misses, and sends cached responses.
_Avoid_: Fast path

**C Boundary**:
The deliberately small part of the system that remains C-compatible because it interacts with eBPF, kernel-facing APIs, or C ABI libraries.
_Avoid_: C layer

**Domain Model**:
The C++ types that express Shinku concepts before they are adapted to a concrete Backend or C Boundary.
_Avoid_: Wrapper types

**Typed Status**:
A structured error result that carries a stable error code and context instead of relying on exceptions or raw errno.
_Avoid_: Return code, exception

**Observability Surface**:
The deleted runtime-facing health, metrics, and status reporting API. A replacement must be designed as a future module before reintroduction.
_Avoid_: Metrics code

### Deployment

**Transparent Cache**:
A cache that can accelerate eligible DNS exchanges without requiring clients or DNS services to address a different application protocol or participate in cache management. Transparency does not imply shared state or independence from network placement.
_Avoid_: Topology-free cache, DNS resolver

**Cache Point**:
The network location at which one Shinku instance can observe a Query and its corresponding Response and can return a Cache Hit correctly. Node-local and DNS-service-local placements are different Cache Points with the same behavioral contract.
_Avoid_: Kubernetes node, sidecar process

**DNS Service Endpoint**:
The destination network endpoint to which a Query passing through Shinku is addressed. Different endpoints may implement different DNS data or policy even for the same question.
_Avoid_: Resolver, upstream identity

**Downstream DNS Forwarder**:
The trusted DNS intermediary on the client side of Shinku that sends Queries through Shinku on behalf of its own clients and may supply ECS client-network information.
_Avoid_: Client IP, resolver

### Backend Lifecycle

**Backend Lifecycle**:
The explicit state flow for probing, configuring, starting, polling, stopping, and destroying a Backend.
_Avoid_: Startup code

**Backend Probe**:
The pre-start capability check that decides whether the selected Backend is supported on the current host with the validated Config. A failed Backend Probe stops startup instead of triggering Backend fallback.
_Avoid_: Warm-up, partial start, health check

**Backend Runner**:
The Host Runtime object that owns Backend lifecycle sequencing and runs a Backend until a Stop Request or backend failure.
_Avoid_: Backend implementation, runtime loop

**Operational Loop**:
The runtime loop required for a backend to keep functioning, such as packet-event polling, cleanup scheduling, and shutdown handling.
_Avoid_: Observability loop

**Process Control**:
The Host Runtime concern that translates process-level termination signals into shutdown requests.
_Avoid_: Runtime loop, backend lifecycle

**Shutdown Request**:
A sticky request for the Host Runtime to stop its Operational Loop and shut down cleanly.
_Avoid_: Exit code, signal handler state

**Stop Condition**:
A Host Runtime source that can produce a Stop Request, such as a process signal, manual control action, or elapsed runtime deadline.
_Avoid_: Backend state, signal handler

**Stop Request**:
The explicit request for the Backend Runner to stop a running Backend, including the reason the stop was requested.
_Avoid_: Backend failure, exit code

**Stop Reason**:
The cause of an orderly Stop Request: Signal for an observed process-termination signal, Manual for an explicit in-process control request, or Timeout for an elapsed runtime deadline. Backend failures and operation-level timeouts are not Stop Reasons.
_Avoid_: Backend error, poll timeout

**Shutdown Report**:
The normal successful result returned by the Backend Runner when it accepts a Stop Request and shuts a Backend down cleanly.
_Avoid_: Run result, backend error, exit code

### Configuration

**Config Schema**:
The canonical shape of runtime configuration, including backend selection and backend-specific sections.
_Avoid_: CLI flags

**Config File**:
The TOML document that provides runtime configuration for the current refactor phase.
_Avoid_: CLI config, env config

**Config Selector Subcommand**:
The narrow command-line entrypoint that selects which Config File to load.
_Avoid_: Env config

**Config Loader**:
The configuration authority that reads a Config File and produces either a validated runtime Config or config diagnostics.
_Avoid_: CLI parser

**Config Validation**:
The startup check that turns a Config File into either a complete runtime Config or typed errors and warnings before any Backend starts.
_Avoid_: Parameter check

**Config Diagnostic**:
A warning or error produced while interpreting a Config File before any Backend starts.
_Avoid_: Log line

**Backend Section**:
The optional part of Config Schema that contains settings for one Backend.
_Avoid_: Backend config blob

**Effective Config**:
The selected Backend configuration plus backend-neutral settings that will actually drive runtime startup.
_Avoid_: Parsed file

### Cache Domain

**Cache Domain Contract**:
The backend-neutral C++ contract that describes cache capacity, cache admission outcomes, stored response metadata, and cleanup behavior before those concepts are adapted to a concrete Backend.
_Avoid_: eBPF cache wrapper, DPDK cache wrapper

**Cache Policy**:
The rules that decide whether a DNS response may enter the cache, how long it may stay, and when it is evicted.
_Avoid_: Cache config

**Cache Capacity**:
The configured maximum number of resident Cache Entries required by the Effective Config. Grouping multiple stored answers inside one storage container does not change how many Cache Entries they consume.
_Avoid_: Suggested size, physical container count

**Cache Response Limit**:
The configured maximum DNS message size that a Cache Hit may emit. A Backend that cannot support this limit, including fields generated or rebound for the current Query, must fail startup instead of silently reducing it.
_Avoid_: Backend buffer size, response size hint

**Cache Key**:
The logical identity of a cached DNS answer within the active Cacheable Query Profile, composed from its Cache Namespace, canonical question name, question type, question class, and every other admitted semantic that can change the answer. Backend-specific hashes are representations of this identity.
_Avoid_: Name hash, BPF map key

**Cache Namespace**:
The component of Cache Key identity that isolates answers learned for one DNS Service Endpoint from answers served for another. It is part of the key rather than a property of a cache instance.
_Avoid_: Physical cache instance, per-endpoint store

**Canonical DNS Name**:
The case-insensitive DNS name identity represented in uncompressed wire format with lowercase labels and a terminating root label.
_Avoid_: Display name, dotted string, name hash

**Cacheable Query Profile**:
The set of DNS query semantics that the Cache Hit Path can interpret without changing response meaning. Queries outside the active profile are Bypasses rather than approximate key matches.
_Avoid_: Supported packet, Cache Key

**Cache Candidate**:
A validated DNS response that DNS Policy has found eligible for caching, but which has not yet passed Store Admission or become a Cache Entry.
_Avoid_: Cache entry, ring event, stored response

**Cache Entry**:
The published stored form of one Cache Candidate. It occupies one unit of Cache Capacity until removed or replaced; after its Cache Entry Lifetime ends it is no longer eligible for Cache Hits even if cleanup has not reclaimed it yet.
_Avoid_: Cache Candidate, storage container

**Cache Entry Kind**:
The mutually exclusive DNS meaning of a Cache Candidate or Cache Entry: Positive, NXDOMAIN, or NODATA.
_Avoid_: Store flags, response flags, truncated fallback

**Cache Entry Lifetime**:
The earliest retained DNS record expiry after which a cached response is no longer safe to serve as a whole. It is distinct from an admission threshold that decides whether a short-lived response is worth storing.
_Avoid_: Minimum-TTL admission, cleanup interval

**Response Template**:
The verbatim upstream DNS message retained by a Cache Entry, from the DNS header to the end of the message. A Cache Hit combines it with the current Query's Transaction ID and Question Section and with aged TTLs; nothing else about the message changes.
_Avoid_: Normalized response, rebuilt message, immutable replay bytes

**Cache Time**:
A monotonic timestamp in the clock domain shared by a concrete Backend's Cache Fill, cleanup, and Cache Hit paths. It has no wall-clock meaning and may be chosen explicitly in tests.
_Avoid_: Wall time, DNS TTL

**TTL-only Freshness**:
The policy in which Cache Entry validity is determined only from retained DNS TTLs and elapsed Cache Time. External systems do not push invalidations into the cache.
_Avoid_: Kubernetes watch, active purge

### Cache Store

**Cache Store**:
The Backend-owned boundary that applies Store Admission to Cache Candidates and removes expired cache entries without deciding DNS eligibility.
_Avoid_: DNS Policy, global cache service

**Store Admission**:
The Cache Store decision to insert, update, replace, or reject an otherwise valid Cache Candidate according to its capacity and eviction strategy.
_Avoid_: DNS validation, packet filtering

**Store Outcome**:
The backend-neutral result of Store Admission: Inserted adds a key without displacing a live entry, Updated refreshes the same key, Replaced displaces a different live entry, and Rejected publishes nothing. Reusing empty or expired storage is Inserted, so cleanup timing does not change the outcome.
_Avoid_: Return code, store error

**Cache Publication**:
The single visibility transition after which a Cache Candidate may be served as a Cache Entry. A successful Store Outcome has crossed this boundary; a failed store operation has not.
_Avoid_: Arena write, admission attempt

### DNS Policy and Data Paths

**DNS Policy**:
The backend-neutral rules that validate an upstream DNS response and decide whether it becomes a Bypass or a Cache Candidate.
_Avoid_: DNS parser, Store Admission

**Negative Cache Admission**:
The DNS Policy setting that decides whether NXDOMAIN or NODATA responses may become Cache Candidates.
_Avoid_: Store flag, backend option

**Cache Hit Path**:
The Data Plane path that serves an eligible DNS query from an existing cache entry without forwarding it upstream. It returns TTLs reduced to account for time already spent in the cache.
_Avoid_: Cache Fill Path, userspace callback

**Cache Hit Semantics**:
The backend-neutral rules for turning an unexpired Cache Entry into the response for the current Query: TTL aging, Transaction ID rebinding, and Question Section preservation. Every Cache Hit Path must satisfy them regardless of the language it is written in.
_Avoid_: Cache Hit Path, store lookup

**Cache Fill Path**:
The Control Plane path that turns an upstream DNS response into a Cache Candidate and attempts to store it for future hits.
_Avoid_: Cache Hit Path, query path

**Bypass**:
A DNS packet intentionally not answered from cache because it is unsupported, unsafe, malformed, expired, or missed.
_Avoid_: Ignore, drop

**Fail-open**:
The cache preserves upstream DNS behavior when it cannot safely answer locally; failures become bypasses or forwarding, not DNS outages.
_Avoid_: Best effort

### Query Correlation

**Pending Query**:
A bounded, short-lived record of an eligible Cache Miss Query's exchange identity and Cache Namespace, retained only long enough to decide whether the corresponding Response may enter the Cache Fill Path.
_Avoid_: Cache Entry, response cache

**Pending Query Capacity**:
The configured maximum number of Pending Queries that one Shinku instance may retain concurrently. It bounds correlation state independently of Cache Capacity.
_Avoid_: Cache Capacity, Cache Entry count

**Pending Query Timeout**:
The configured maximum inactivity interval after the most recent observation of the same pending exchange. An identical Query refreshes the interval; a Response arriving after it elapses cannot use that record to enter the Cache Fill Path.
_Avoid_: DNS TTL, Cache Entry Lifetime

**Query Correlation**:
The validation that a Response corresponds to a live Pending Query and preserves the Query identity, Cache Namespace, and eligibility needed for Cache Fill. It authorizes cache admission for that exchange but does not establish cryptographic authenticity of the DNS answer.
_Avoid_: DNSSEC validation, source trust

### ECS

**ECS Pass-through**:
The behavior in which Shinku leaves an ECS-bearing Query and its Response to the existing DNS path without serving or publishing a Cache Entry for that exchange.
_Avoid_: ECS-aware caching, ignore ECS

**ECS-aware Caching**:
The capability to validate correlated ECS Query and Response semantics, store answers with their ECS coverage, select a safe matching Cache Entry, and bind the response to the current Query on a Cache Hit.
_Avoid_: ECS Pass-through, ECS key field
