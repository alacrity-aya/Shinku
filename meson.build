project('shinku', 'c', 'cpp',
  version: '0.1',
  default_options: [
    'warning_level=2',    
    'werror=false',       
    'b_sanitize=address',
    'buildtype=debug',
    'b_lundef=false',
    'cpp_std=c++26'
  ]
)

# Build options
bpf_log = get_option('bpf_log')
build_benchmark_bin = get_option('build_benchmark_bin')
dns_fuzzing = get_option('dns_fuzzing')

libbpf_dep = dependency('libbpf', version: '>=1.3.0')
libcap_dep = dependency('libcap', fallback : ['libcap', 'libcap_dep'])
tomlplusplus_dep = dependency(
  'tomlplusplus',
  fallback : ['tomlplusplus', 'tomlplusplus_dep'],
  default_options : ['compile_library=false']
)
argparse_dep = dependency('argparse', fallback : ['argparse', 'argparse_dep'])
spdlog_dep = dependency('spdlog', version: '==1.17.0', fallback : ['spdlog', 'spdlog_dep'])
dpdk_dep = dependency('libdpdk')
dpdk_libdir = dpdk_dep.get_variable(pkgconfig: 'libdir')
cpp_compiler = meson.get_compiler('cpp')
rte_net_ring_dep = cpp_compiler.find_library('rte_net_ring', dirs: [dpdk_libdir])
dpdk_rpath_args = ['-Wl,--disable-new-dtags']
clang = find_program('clang')
bpftool = find_program('bpftool')
python3 = find_program('python3')

version_conf = configuration_data()
version_conf.set('SHINKU_VERSION', meson.project_version())
version_header = configure_file(
  input: 'src/generated/version.h.in',
  output: 'version.h',
  configuration: version_conf
)

vmlinux_h = custom_target(
  'vmlinux.h',
  output: 'vmlinux.h',
  command: [
    bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'
  ],
  capture: true
)

inc_src = include_directories('src/include', 'src')

# ====================
# Main BPF Program
# ====================
bpf_obj = custom_target(
  'cache.bpf.o',
  input: [
    'src/bpf/cache.bpf.c',
    'src/bpf/cache_bpf_common.h',
    'src/bpf/cache_bpf_state.h',
    'src/bpf/cache_bpf_parse.h',
    'src/bpf/cache_bpf_fingerprint.h',
    'src/bpf/cache_bpf_snapshot.h',
    'src/bpf/cache_bpf_pending.h',
  ],
  output: 'cache.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
  ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + [
    '-I' + meson.current_build_dir(),
    '-I' + meson.current_source_dir() + '/src/include',
    '-I' + meson.current_source_dir() + '/src',
    '-c', '@INPUT0@', '-o', '@OUTPUT@'
  ]
)

# Dummy XDP pass-through (needed on veth peer for XDP_TX to work)
xdp_pass_obj = custom_target(
  'xdp_pass.bpf.o',
  input: 'src/bpf/xdp_pass.bpf.c',
  output: 'xdp_pass.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-I' + meson.current_build_dir(),
    '-c', '@INPUT@', '-o', '@OUTPUT@'
  ]
)

bpf_skel = custom_target(
  'cache.skel.h',
  input: bpf_obj,
  output: 'cache.skel.h',
  command: [
    bpftool, 'gen', 'skeleton', '@INPUT@'
  ],
  capture: true
)

# CLI entry point
process_control_src = files(
  'src/process_control/process_control.cc',
)

backend_src = files(
  'src/backend/backend_runner.cc',
  'src/backend/stop_condition.cc',
)

cache_dns_policy_src = files(
  'src/cache/dns_policy.cc',
  'src/cache/dns/response_policy.cc',
  'src/cache/dns/wire_parser.cc',
)

ebpf_backend_src = files(
  'src/backend/ebpf/ebpf_backend.cc',
  'src/backend/ebpf/cleanup_worker.cc',
  'src/backend/ebpf/ebpf_native_session.cc',
  'src/backend/ebpf/cache/correlated_dns_event_consumer.cc',
  'src/backend/ebpf/cache/ebpf_cache_map.cc',
  'src/backend/ebpf/cache/ebpf_cache_secret.cc',
  'src/backend/ebpf/cache/ebpf_cache_storage_layout.cc',
  'src/backend/ebpf/cache/ebpf_cache_store.cc',
  'src/backend/ebpf/cache/ebpf_pending_query_map.cc',
  'src/backend/ebpf/cache/pending_query_cleaner.cc',
)

dpdk_backend_src = files(
  'src/backend/dpdk/dpdk_backend.cc',
  'src/backend/dpdk/dpdk_pending_store.cc',
  'src/backend/dpdk/dpdk_cleanup_tasks.cc',
  'src/backend/dpdk/dpdk_time.cc',
  'src/backend/dpdk/dpdk_cache_store.cc',
  'src/backend/dpdk/dpdk_dns_packet.cc',
  'src/backend/dpdk/dpdk_hash_table.cc',
  'src/backend/dpdk/dpdk_eal.cc',
  'src/backend/dpdk/dpdk_packet_pool.cc',
  'src/backend/dpdk/dpdk_packet_path.cc',
  'src/backend/dpdk/dpdk_port.cc',
  'src/backend/dpdk/dpdk_scheduler.cc',
)

backend_creation_src = files(
  'src/backend/backend_creation.cc',
)

cli_src = files(
  'src/cli/main.cc',
  'src/cli/cli.cc',
  'src/config/toml_loader.cc',
) + process_control_src + backend_src + cache_dns_policy_src + ebpf_backend_src + dpdk_backend_src + backend_creation_src

executable(
  'shinku',
  cli_src,
  bpf_skel,
  version_header,
  dependencies: [libbpf_dep, libcap_dep, tomlplusplus_dep, argparse_dep, spdlog_dep, dpdk_dep, rte_net_ring_dep],
  include_directories: inc_src,
  build_rpath: dpdk_libdir,
  install_rpath: dpdk_libdir,
  link_args: dpdk_rpath_args,
  c_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
  cpp_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
  install: true
)

if build_benchmark_bin
  executable(
    'shinku_bench',
    cli_src,
    bpf_skel,
    version_header,
    dependencies: [libbpf_dep, libcap_dep, tomlplusplus_dep, argparse_dep, spdlog_dep, dpdk_dep, rte_net_ring_dep],
    include_directories: inc_src,
    build_rpath: dpdk_libdir,
    link_args: dpdk_rpath_args,
    c_args: [
      '-O3',
      '-DNDEBUG',
    ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
    cpp_args: [
      '-O3',
      '-DNDEBUG',
    ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
    override_options: [
      'b_sanitize=none',
      'buildtype=release',
      'optimization=3',
      'debug=false',
    ],
    install: false
  )
endif

# ====================
# Tests
# ====================
subdir('tests/unit')
subdir('tests/integration')

if dns_fuzzing
  subdir('tests/fuzz')
endif

# ====================
# Static Analysis (clang-tidy)
# ====================
clang_tidy = find_program('clang-tidy', required: false)

if clang_tidy.found()
  run_target('tidy',
    command: [
      meson.current_source_dir() / 'scripts/run-clang-tidy.sh'
    ]
  )
  
  run_target('tidy-fix',
    command: [
      meson.current_source_dir() / 'scripts/run-clang-tidy.sh', '--fix'
    ]
  )
endif

# ====================
# Documentation (Doxygen)
# ====================
doxygen = find_program('doxygen', required: false)

if doxygen.found()
  doxyfile = configure_file(
    input: 'Doxyfile.in',
    output: 'Doxyfile',
    configuration: {
      'PROJECT_NAME': meson.project_name(),
      'PROJECT_VERSION': meson.project_version(),
      'INPUT_DIR': meson.current_source_dir() / 'src',
      'OUTPUT_DIR': meson.current_build_dir() / 'docs',
      'DOXYGEN_AWESOME_CSS_DIR': meson.current_source_dir() / 'docs' / 'doxygen-awesome-css',
    }
  )

  run_target('docs',
    command: [doxygen, doxyfile]
  )

  run_target('doc',
    command: [doxygen, doxyfile]
  )
endif
