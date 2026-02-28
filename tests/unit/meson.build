# Unit Tests

# ====================
# DNS Hash Test (userspace, no BPF)
# ====================
dns_hash_test_exe = executable(
    'dns_hash_verify',
    'hash/dns_hash_test.c',
    files(
      '../../src/core/hash.c',
      '../../src/core/dns_parser.c',

    ),
    native: true,
    dependencies: [libbpf_dep],
    c_args: ['-g', '-O2', '-D__BPF__=0'],
    include_directories: inc_src
)

test('DNS Hash Consistency Check', dns_hash_test_exe)

# ====================
# DNS Parser Test (userspace, no BPF)
# ====================
dns_parser_test_exe = executable(
    'dns_parser_test',
    'parser/dns_parser_test.c',
    files(
      '../../src/core/hash.c',
      '../../src/core/dns_parser.c',
    ),
    native: true,
    dependencies: [libbpf_dep],
    c_args: ['-g', '-O2', '-D__BPF__=0'],
    include_directories: inc_src
)

test('DNS Parser Test', dns_parser_test_exe)

# ====================
# Arena List Test
# ====================
arena_inc = include_directories('../../src/bpf/arena', '../../src/include', '../../src')

arena_list_bpf_obj = custom_target(
  'arena_list.bpf.o',
  input: 'arena/arena_list.bpf.c',
  output: 'arena_list.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DBPF_NO_KFUNC_PROTOTYPES',
    '-I' + meson.project_build_root(),
    '-I' + meson.project_source_root() + '/src/bpf/arena',
    '-I' + meson.project_source_root() + '/src/include',
    '-I' + meson.project_source_root() + '/src',
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

arena_list_test_exe = executable(
    'arena_list_test',
    'arena/arena_list_test.c',
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
  input: 'arena/arena_htab.bpf.c',
  output: 'arena_htab.bpf.o',
  depends: vmlinux_h,
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-DBPF_NO_KFUNC_PROTOTYPES',
    '-I' + meson.project_build_root(),
    '-I' + meson.project_source_root() + '/src/bpf/arena',
    '-I' + meson.project_source_root() + '/src/include',
    '-I' + meson.project_source_root() + '/src',
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

arena_htab_test_exe = executable(
    'arena_htab_test',
    'arena/arena_htab_test.c',
    arena_htab_skel,
    dependencies: libbpf_dep,
    include_directories: [inc_src, arena_inc],
    override_options: ['b_sanitize=none'],
)

test('Arena Hash Table Test', arena_htab_test_exe)


# ====================
# CAREs Expand Test 
# ====================

cares_expand_test_exe = executable(
    'cares_expand_test',
    'cares/cares_expand_test.c',
    dependencies: cares_dep,
)

test('Flat DNS Packet test Test', cares_expand_test_exe)

# ====================
# DNS Benchmark (manual, not a test)
# ====================
dns_bench_exe = executable(
    'dns_bench',
    'bench/dns_bench.c',
    files(
      '../../src/core/hash.c',
      '../../src/core/dns_parser.c',
    ),
    native: true,
    dependencies: [libbpf_dep],
    c_args: ['-g', '-O2', '-D__BPF__=0'],
    include_directories: inc_src
)
