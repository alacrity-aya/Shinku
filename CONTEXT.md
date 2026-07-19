# Shinku Refactor Context

This glossary defines project language for the C++/DPDK refactor. It intentionally avoids module-level implementation details.

## Language

**Cache Engine**:
A pluggable runtime that receives DNS packets, checks the cache, forwards misses, and emits cache events.
_Avoid_: Loader, dataplane module

**Backend**:
A concrete Cache Engine implementation for one packet-processing environment.
_Avoid_: Mode, driver

**Backend Lifecycle**:
The explicit state flow for probing, configuring, starting, polling, stopping, and destroying a Backend.
_Avoid_: Startup code

**Backend Probe**:
The pre-start capability check that decides whether the selected Backend is supported on the current host with the validated Config.
_Avoid_: Warm-up, partial start

**Control Plane**:
The management path that owns configuration, lifecycle, response validation, cache insertion, eviction, and shutdown.
_Avoid_: CLI, userspace loop

**Domain Model**:
The C++ types that express Shinku concepts before they are adapted to a concrete Backend or C Boundary.
_Avoid_: Wrapper types

**Config Schema**:
The canonical shape of runtime configuration, including backend selection and backend-specific sections.
_Avoid_: CLI flags

**Config File**:
The TOML document that provides runtime configuration for the current refactor phase.
_Avoid_: CLI config, env config

**Cache Policy**:
The rules that decide whether a DNS response may enter the cache, how long it may stay, and when it is evicted.
_Avoid_: Cache config

**Backend-neutral**:
A rule or type that applies equally to all Backends instead of belonging to eBPF or DPDK specifically.
_Avoid_: Shared by accident

**Config Selector Subcommand**:
The narrow command-line entrypoint that selects which Config File to load.
_Avoid_: Env config

**Config Validation**:
The startup check that turns a Config File into either a complete runtime Config or typed errors and warnings before any Backend starts.
_Avoid_: Parameter check

**Effective Config**:
The selected Backend configuration plus backend-neutral settings that will actually drive runtime startup.
_Avoid_: Parsed file

**Config Loader**:
The configuration authority that reads a Config File and produces either a validated runtime Config or config diagnostics.
_Avoid_: CLI parser

**Config Diagnostic**:
A warning or error produced while interpreting a Config File before any Backend starts.
_Avoid_: Log line

**Backend Section**:
The optional part of Config Schema that contains settings for one Backend.
_Avoid_: Backend config blob

**Typed Status**:
A structured error result that carries a stable error code and context instead of relying on exceptions or raw errno.
_Avoid_: Return code, exception

**Host Runtime**:
The non-eBPF process code that runs in userspace and owns process lifecycle, backends, cache policy, and control-plane work.
_Avoid_: Userspace code

**Data Plane**:
The packet path that parses DNS queries, performs cache lookup, forwards misses, and sends cached responses.
_Avoid_: Fast path

**C Boundary**:
The deliberately small part of the system that remains C-compatible because it interacts with eBPF, kernel-facing APIs, or C ABI libraries.
_Avoid_: C layer

**DPDK Backend**:
The Cache Engine that uses DPDK packet I/O and userspace packet buffers.
_Avoid_: DPDK mode

**eBPF Backend**:
The runnable Cache Engine that uses eBPF programs for packet handling and must remain operational during the refactor.
_Avoid_: Legacy backend

**Observability Surface**:
The deleted runtime-facing health, metrics, and status reporting API. A replacement must be designed as a future module before reintroduction.
_Avoid_: Metrics code

**Operational Loop**:
The runtime loop required for a backend to keep functioning, such as packet-event polling, cleanup scheduling, and shutdown handling.
_Avoid_: Observability loop

**Process Control**:
The Host Runtime concern that translates process-level termination signals into shutdown requests.
_Avoid_: Runtime loop, backend lifecycle

**Shutdown Request**:
A sticky request for the Host Runtime to stop its Operational Loop and shut down cleanly.
_Avoid_: Exit code, signal handler state

**Fail-open**:
The cache preserves upstream DNS behavior when it cannot safely answer locally; failures become bypasses or forwarding, not DNS outages.
_Avoid_: Best effort

**Bypass**:
A DNS packet intentionally not answered from cache because it is unsupported, unsafe, malformed, expired, or missed.
_Avoid_: Ignore, drop
