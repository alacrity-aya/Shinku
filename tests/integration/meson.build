dpdk_ring_smoke_test_exe = executable(
  'dpdk_ring_smoke_test',
  'dpdk_ring_smoke_test.cc',
  backend_src,
  cache_dns_policy_src,
  dpdk_backend_src,
  dependencies: [spdlog_dep, dpdk_dep, rte_net_ring_dep],
  include_directories: inc_src,
  build_rpath: dpdk_libdir,
  link_args: dpdk_rpath_args,
)

test(
  'DPDK Ring Smoke Test',
  dpdk_ring_smoke_test_exe,
  args: [
    '--no-huge',
    '--no-pci',
    '--in-memory',
    '--no-telemetry',
    '--vdev=net_ring0',
    '--vdev=net_ring1',
  ],
  env: ['XDG_RUNTIME_DIR=' + meson.current_build_dir()],
  timeout: 30,
)

dpdk_cache_path_test_exe = executable(
  'dpdk_cache_path_test',
  'dpdk_cache_path_test.cc',
  cache_dns_policy_src,
  files(
    '../../src/backend/dpdk/dpdk_cache_store.cc',
    '../../src/backend/dpdk/dpdk_dns_packet.cc',
    '../../src/backend/dpdk/dpdk_hash_table.cc',
    '../../src/backend/dpdk/dpdk_pending_store.cc',
    '../../src/backend/dpdk/dpdk_packet_path.cc',
    '../../src/backend/dpdk/dpdk_scheduler.cc',
    '../../src/backend/dpdk/dpdk_time.cc',
  ),
  dependencies: [spdlog_dep, dpdk_dep],
  include_directories: inc_src,
  build_rpath: dpdk_libdir,
  link_args: dpdk_rpath_args,
)

test(
  'DPDK Cache Path Test',
  dpdk_cache_path_test_exe,
  args: ['--no-huge', '--no-pci', '--in-memory', '--no-telemetry'],
  env: ['XDG_RUNTIME_DIR=' + meson.current_build_dir()],
  timeout: 30,
)

dpdk_port_count_test_exe = executable(
  'dpdk_port_count_test',
  'dpdk_port_count_test.cc',
  '../../src/backend/dpdk/dpdk_eal.cc',
  '../../src/backend/dpdk/dpdk_packet_pool.cc',
  '../../src/backend/dpdk/dpdk_port.cc',
  dependencies: [spdlog_dep, dpdk_dep, rte_net_ring_dep],
  include_directories: inc_src,
  build_rpath: dpdk_libdir,
  link_args: dpdk_rpath_args,
)

test(
  'DPDK Port Count Test',
  dpdk_port_count_test_exe,
  args: [
    '--no-huge',
    '--no-pci',
    '--in-memory',
    '--no-telemetry',
    '--vdev=net_ring0',
  ],
  env: ['XDG_RUNTIME_DIR=' + meson.current_build_dir()],
  timeout: 30,
)
