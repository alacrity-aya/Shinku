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

# ====================
# Core Library
# ====================
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

# ====================
# Unit Tests
# ====================

# DNS Hash Test (userspace, no BPF)
dns_hash_test_exe = executable(
    'dns_hash_verify',
    'tests/unit/hash/dns_hash_test.c',
    'src/core/hash.c',
    'src/core/dns_parser.c',
    native: true,
    c_args: ['-g', '-O2', '-D__BPF__=0'],
    include_directories: inc_src
)

test('DNS Hash Consistency Check', dns_hash_test_exe)

# ====================
# Arena List Test
# ====================

# Arena BPF program
arena_inc = include_directories('src/bpf/arena', 'src/include', 'src')

arena_list_bpf_obj = custom_target(
  'arena_list.bpf.o',
  input: 'tests/unit/arena/arena_list.bpf.c',
  output: 'arena_list.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DBPF_NO_KFUNC_PROTOTYPES',
    '-I' + meson.current_build_dir(),      
    '-I' + meson.current_source_dir() + '/src/bpf/arena',
    '-I' + meson.current_source_dir() + '/src/include',
    '-I' + meson.current_source_dir() + '/src',
    '-c', '@INPUT@', '-o', '@OUTPUT@'
  ]
)

arena_list_skel = custom_target(
  'arena_list.skel.h',
  input: arena_list_bpf_obj,
  output: 'arena_list.skel.h',
  command: [
    bpftool, 'gen', 'skeleton', '@INPUT@'
  ],
  capture: true
)

# Arena list test executable (disable ASAN - BPF Arena uses high memory addresses)
arena_list_test_exe = executable(
    'arena_list_test',
    'tests/unit/arena/arena_list_test.c',
    arena_list_skel,
    dependencies: libbpf_dep,
    include_directories: [inc_src, arena_inc],
    override_options: ['b_sanitize=none'],
)

test('Arena List Test', arena_list_test_exe)

# ====================
# Arena Hash Table Test
# ====================

arena_htab_bpf_obj = custom_target(
  'arena_htab.bpf.o',
  input: 'tests/unit/arena/arena_htab.bpf.c',
  output: 'arena_htab.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DBPF_NO_KFUNC_PROTOTYPES',
    '-I' + meson.current_build_dir(),      
    '-I' + meson.current_source_dir() + '/src/bpf/arena',
    '-I' + meson.current_source_dir() + '/src/include',
    '-I' + meson.current_source_dir() + '/src',
    '-c', '@INPUT@', '-o', '@OUTPUT@'
  ]
)

arena_htab_skel = custom_target(
  'arena_htab.skel.h',
  input: arena_htab_bpf_obj,
  output: 'arena_htab.skel.h',
  command: [
    bpftool, 'gen', 'skeleton', '@INPUT@'
  ],
  capture: true
)

# Arena hash table test executable (disable ASAN - BPF Arena uses high memory addresses)
arena_htab_test_exe = executable(
    'arena_htab_test',
    'tests/unit/arena/arena_htab_test.c',
    arena_htab_skel,
    dependencies: libbpf_dep,
    include_directories: [inc_src, arena_inc],
    override_options: ['b_sanitize=none'],
)

test('Arena Hash Table Test', arena_htab_test_exe)
