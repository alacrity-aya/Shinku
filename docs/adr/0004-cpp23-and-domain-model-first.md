# C++23 and Config Domain First

Shinku will target C++23 for Host Runtime code and introduce the new C++ domain model before implementing the DPDK backend. The first practical C++ slice is the Config domain model and TOML Config File loader; `src/cli` is deferred as a thin config-selector subcommand instead of becoming the full configuration authority.

**Considered Options**

- Use compiler-tracking `c++2c` to chase the newest available language mode.
- Keep C-style structs and APIs until DPDK is implemented.
- Target C++23, migrate `src/cli` first, and introduce the C++ domain model before backend expansion.
- Target C++23, introduce Config/TOML first, and defer CLI parsing as a thin config-selector subcommand.

**Consequences**

C++23 gives a modern but stable toolchain baseline. Introducing the Config domain model before DPDK avoids designing DPDK around legacy C structs or legacy CLI flags, but requires adapters so the current eBPF backend remains runnable during migration.
