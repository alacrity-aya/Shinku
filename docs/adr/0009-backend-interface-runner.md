# Backend Interface and Runner

Shinku will introduce a C++23 backend lifecycle interface in `src/backend/`. The public backend abstraction is a normal pure virtual `Backend` class with `probe()`, `start()`, `poll_once()`, and `stop()`. CRTP is not part of the public interface because backend selection is runtime-configured through the validated Config model; CRTP may be used later only as a private implementation helper if it removes real duplication.

`probe()` is a pure pre-start capability gate. It may inspect validated configuration and host capabilities, but it must not attach programs, create maps, bind ports, reserve hugepages, spawn threads, or mutate process/global state. It returns `std::expected<ProbeResult, BackendError>`, where `ProbeStatus::Unsupported` is a capability conclusion and `BackendErrorCode::ProbeFailed` is an execution failure while probing.

`BackendRunner` owns lifecycle sequencing for `Created -> Running -> Stopped -> Failed`. Backend implementations own backend-specific resource actions only. `poll_once()` returns quickly and reports idle work as `PollStatus::NoWork`. `stop()` is idempotent; backend lifecycle failures are reported through `std::expected`, not exceptions. `BackendRunner` also performs best-effort stop in its destructor and discards the returned status because destructors cannot report typed errors. Module 6 does not introduce a production `BackendFactory`; backend creation moves to the eBPF Backend Module once a real C++ eBPF backend exists.

**Considered Options**

- Use CRTP as the public interface.
- Use `std::variant` or type erasure for all backends immediately.
- Let each backend implementation maintain its own lifecycle state.
- Introduce a production factory before any concrete C++ backend exists.
- Keep `probe()` as a startup-only capability check and drive progress through a runner-owned synchronous loop.

**Consequences**

The first backend contract is small, testable, and independent of current eBPF loader shape. Runtime backend choice remains possible without forcing compile-time templates into the public API. A single runner prevents eBPF and DPDK lifecycle behavior from drifting. Startup must fail when the selected backend is unsupported; it must not silently switch backend or storage mode. Real eBPF wiring remains in the next module, so Module 6 can be validated with fake backend tests.
