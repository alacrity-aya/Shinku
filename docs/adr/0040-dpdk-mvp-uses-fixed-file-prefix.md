# DPDK MVP Uses a Fixed File Prefix

Status: accepted

Module 9 always initializes EAL with `--file-prefix=shinku`. It does not generate a process-specific suffix and does not
expose `file_prefix` or `instance_name` through Config. The MVP therefore supports only one active Shinku DPDK primary
within a host/runtime-directory resource domain.

If an active instance already owns the `shinku` EAL resource domain, another Shinku process fails startup. It does not
attach as a secondary, reinterpret itself as another instance, or retry with a generated prefix. This keeps deployment
identity out of the current Config and matches the accepted requirement that concurrent Shinku DPDK primaries are out
of scope.

Supporting multiple independent primaries later requires an explicit design for stable instance identity,
resource-directory and hugepage-file isolation, diagnostics, collision handling, and stale-resource operations. It is
not introduced as an incidental EAL argument.
