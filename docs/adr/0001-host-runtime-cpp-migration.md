# Host Runtime C++ Migration

Shinku will migrate all Host Runtime `.c` files to C++ over the refactor, while keeping C for eBPF programs, generated skeleton interaction, and intentionally small C ABI boundaries. This is a gradual migration, not a rewrite that discards the existing DNS/cache behavior.

**Considered Options**

- Keep proven DNS/cache modules in C permanently and write only the new backend layer in C++.
- Rewrite the whole project from scratch in C++.
- Gradually migrate Host Runtime files to C++ while preserving behavior tests and keeping required C boundaries.

**Consequences**

The build must become mixed C/C++ early. Tests must stay green through each conversion slice, because the existing C implementation is the behavior oracle during the refactor.
