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
build_benchmark_bin = get_option('build_benchmark_bin')
ecs = get_option('ecs')

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
inc_runtime = include_directories('src/runtime')

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
  ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + (obs_bpf ? ['-DSHINKU_OBS_BPF_ENABLED=1'] : ['-DSHINKU_OBS_BPF_ENABLED=0']) + (ecs ? ['-DSHINKU_ECS_ENABLED=1'] : ['-DSHINKU_ECS_ENABLED=0']) + [
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
  'src/runtime/events.c',
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
  include_directories: [inc_src, inc_runtime],
  c_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + (obs ? ['-DSHINKU_OBS_ENABLED=1'] : ['-DSHINKU_OBS_ENABLED=0']) + (ecs ? ['-DSHINKU_ECS_ENABLED=1'] : ['-DSHINKU_ECS_ENABLED=0']),
  install: true
)

if build_benchmark_bin
  executable(
    'shinku_bench',
    cli_src,
    core_src,
    bpf_skel,
    dependencies: [libbpf_dep],
    include_directories: [inc_src, inc_runtime],
    c_args: [
      '-O3',
      '-DNDEBUG',
    ] + (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']) + (obs ? ['-DSHINKU_OBS_ENABLED=1'] : ['-DSHINKU_OBS_ENABLED=0']) + (ecs ? ['-DSHINKU_ECS_ENABLED=1'] : ['-DSHINKU_ECS_ENABLED=0']),
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
