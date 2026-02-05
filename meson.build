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

bpf_obj = custom_target(
  'cache.bpf.o',
  input: 'src/cache.bpf.c',
  output: 'cache.bpf.o',
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

executable(
  'cache-monitor',
  'src/main.c',
  bpf_skel, 
  dependencies: libbpf_dep,
  install: true
)
