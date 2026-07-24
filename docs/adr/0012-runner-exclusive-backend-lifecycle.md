# Backend Lifecycle Is Runner-Exclusive

`BackendRunner` is the only object allowed to invoke `Backend::probe()`, `start()`, `poll()`, and `stop()`. Module 8A enforces this rule with C++ access control rather than convention: lifecycle virtual functions and concrete overrides become protected runner-owned hooks, while `Backend` grants access to `BackendRunner` through friendship. Concrete Backend tests drive lifecycle through `BackendRunner`; this supersedes the direct eBPF lifecycle-test exception recorded in ADR-0010.

`BackendRunner` remains responsible for calling `stop()` after partial startup failure. Backend implementations retain only resource-acquisition state needed for idempotent cleanup and use RAII destruction as a final `noexcept` release path, not as an alternative lifecycle controller.
