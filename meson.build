# Meson build configuration for the eBPF-based DNS cache project.
# This build script defines the project, its dependencies, and the build targets for both the eBPF program and the user-space application.
project('ebpf-cache-project', 'c', 
  version: '0.1',
  default_options: [
    'warning_level=2',    
    'werror=false',       
    'b_sanitize=address',
    'buildtype=debug',
    'b_lundef=false'
  ]
)

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

bpf_obj = custom_target(
  'cache.bpf.o',
  input: 'src/bpf/cache.bpf.c',
  output: 'cache.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DENABLE_BPF_LOG',
    '-I' + meson.current_build_dir(),      
    '-I' + meson.current_source_dir() + '/src/include',
    '-I' + meson.current_source_dir() + '/src',
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

# Core library (shared between CLI and tests)
core_src = files(
  'src/core/hash.c',
  'src/core/dns_parser.c',
  'src/core/loader.c',
)

# CLI entry point
cli_src = files(
  'src/cli/main.c',
  'src/cli/config.c',
)

executable(
  'dns-cache',
  cli_src,
  core_src,          
  bpf_skel,         
  dependencies: libbpf_dep,
  include_directories: inc_src, 
  install: true
)

dns_hash_test_exe = executable(
    'dns_hash_verify',
    'tests/unit/dns_hash_test.c',
    'src/core/hash.c',
    'src/core/dns_parser.c',
    native: true,
    c_args: ['-g', '-O2', '-D__BPF__=0'],
    include_directories: inc_src
)

test('DNS Hash Consistency Check', dns_hash_test_exe)