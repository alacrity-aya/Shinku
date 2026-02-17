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

inc_src = include_directories('src')

bpf_obj = custom_target(
  'cache.bpf.o',
  input: 'src/bpf/cache.bpf.c',
  output: 'cache.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DENABLE_BPF_LOG',
    '-I' + meson.current_build_dir(),      
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

user_src = files(
  'src/user/main.c',
  'src/user/config.c',
  'src/user/loader.c',
  'src/user/parser.c',
)

executable(
  'dns-cache',
  user_src,          
  bpf_skel,         
  dependencies: libbpf_dep,
  include_directories: inc_src, 
  install: true
)

dns_hash_test_exe = executable(
    'dns_hash_verify',
    'tests/dns_hash_test.c',
    'src/utils/hash.c',
    'src/user/parser.c',  # Add parser.c to get access to the testable functions
    native: true,
    c_args: ['-g', '-O2', '-D__BPF__=0'],  # Define __BPF__ as 0 for userspace
    include_directories: inc_src
)

test('DNS Hash Consistency Check', dns_hash_test_exe)
