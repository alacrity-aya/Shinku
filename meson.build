# Meson build configuration for the eBPF-based DNS cache project.
# This build script defines the project, its dependencies, and the build targets for both the eBPF program and the user-space application.
project('shinku', 'c',
  version: '0.1',
  default_options: [
    'warning_level=2',    
    'werror=false',       
    'b_sanitize=address',
    'buildtype=debug',
    'b_lundef=false'
  ]
)

# Build options
bpf_log = get_option('bpf_log')
obs = get_option('obs')
obs_bpf = get_option('obs_bpf')

cares_dep = dependency('libcares', fallback : ['c-ares', 'cares_dep'])
libbpf_dep = dependency('libbpf')
clang = find_program('clang')
bpftool = find_program('bpftool')

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
  input: 'src/bpf/cache.bpf.c',
  output: 'cache.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
  ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + (obs_bpf ? ['-DSHINKU_OBS_BPF_ENABLED=1'] : ['-DSHINKU_OBS_BPF_ENABLED=0']) + [
    '-I' + meson.current_build_dir(),
    '-I' + meson.current_source_dir() + '/src/include',
    '-I' + meson.current_source_dir() + '/src',
    '-c', '@INPUT@', '-o', '@OUTPUT@'
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

# Core Library
core_src = files(
  'src/core/degraded_mode.c',
  'src/core/hash.c',
  'src/core/dns_parser.c',
  'src/core/obs_metrics.c',
  'src/core/obs_http.c',
  'src/core/loader.c',

)

# CLI entry point
cli_src = files(
  'src/cli/main.c',
  'src/cli/config.c',
)

executable(
  'shinku',
  cli_src,
  core_src,          
  bpf_skel,         
  dependencies: [libbpf_dep],
  include_directories: inc_src, 
  c_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + (obs ? ['-DSHINKU_OBS_ENABLED=1'] : ['-DSHINKU_OBS_ENABLED=0']),
  install: true
)

# ====================
# Tests
# ====================
subdir('tests/unit')

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
