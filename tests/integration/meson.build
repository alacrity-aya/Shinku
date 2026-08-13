dpdk_ring_smoke_test_exe = executable(
  'dpdk_ring_smoke_test',
  'dpdk_ring_smoke_test.cc',
  backend_src,
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

dpdk_port_count_test_exe = executable(
  'dpdk_port_count_test',
  'dpdk_port_count_test.cc',
  '../../src/backend/dpdk/dpdk_native_session.cc',
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
