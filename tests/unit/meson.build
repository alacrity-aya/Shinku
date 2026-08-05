# Unit Tests

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


catch2_with_main_dep = dependency(
    'catch2-with-main',
    fallback : ['catch2', 'catch2_with_main_dep'],
    default_options : ['tests=false', 'install=false'],
)

# ====================
# C++ Config Loader Test
# ====================
config_loader_test_exe = executable(
    'config_loader_test',
    'config/config_loader_test.cc',
    files(
      '../../src/config/toml_loader.cc',
    ),
    dependencies: [tomlplusplus_dep, catch2_with_main_dep],
    include_directories: inc_src,
)

test('Config Loader Test', config_loader_test_exe)

# ====================
# C++ Cache Domain Contract Tests
# ====================
cache_hit_vector_file = configure_file(
    input: '../vectors/cache_hit/generate.py',
    output: 'cache_hit_vectors.toml',
    command: [python3, '@INPUT@', '@OUTPUT@'],
)

cache_domain_test_exe = executable(
    'cache_domain_test',
    files(
      'cache/cache_domain_test.cc',
      'cache/fake_cache_store_test.cc',
      'cache/cache_hit_vector_test.cc',
    ),
    dependencies: [tomlplusplus_dep, catch2_with_main_dep, dependency('threads')],
    include_directories: inc_src,
    cpp_args: [
      '-DCACHE_HIT_VECTOR_FILE="' + meson.current_build_dir() / 'cache_hit_vectors.toml' + '"',
    ],
)

test('Cache Domain Contract Test', cache_domain_test_exe)

# ====================
# C++ DNS Policy Engine Tests
# ====================
query_eligibility_vector_file = configure_file(
    input: '../vectors/query_eligibility/generate.py',
    output: 'query_eligibility_vectors.toml',
    command: [python3, '@INPUT@', '@OUTPUT@'],
)

dns_policy_test_exe = executable(
    'dns_policy_test',
    files(
      'cache/dns_policy_test.cc',
      'cache/fuzz_input_test.cc',
      'cache/query_eligibility_vector_test.cc',
      'cache/dns_response_policy_test.cc',
      'cache/dns_wire_parser_test.cc',
    ),
    cache_dns_policy_src,
    dependencies: [tomlplusplus_dep, catch2_with_main_dep],
    include_directories: [inc_src, include_directories('../fuzz')],
    cpp_args: [
      '-DQUERY_ELIGIBILITY_VECTOR_FILE="' + meson.current_build_dir() / 'query_eligibility_vectors.toml' + '"',
    ],
)

test('DNS Policy Engine Test', dns_policy_test_exe)

# ====================
# C++ eBPF Cache Store Tests
# ====================
ebpf_cache_store_test_exe = executable(
    'ebpf_cache_store_test',
    files(
      'backend/ebpf_cache_store_test.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_map.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_secret.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_storage_layout.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_store.cc',
    ),
    dependencies: [libbpf_dep, catch2_with_main_dep, dependency('threads')],
    include_directories: inc_src,
)

test('eBPF Cache Store Test', ebpf_cache_store_test_exe)

pending_query_cleaner_test_exe = executable(
    'pending_query_cleaner_test',
    files(
      'backend/pending_query_cleaner_test.cc',
      '../../src/backend/ebpf/cache/ebpf_pending_query_map.cc',
      '../../src/backend/ebpf/cache/pending_query_cleaner.cc',
    ),
    dependencies: [libbpf_dep, catch2_with_main_dep],
    include_directories: inc_src,
)

test('Pending Query Cleaner Test', pending_query_cleaner_test_exe)

correlated_dns_event_consumer_test_exe = executable(
    'correlated_dns_event_consumer_test',
    files(
      'backend/correlated_dns_event_consumer_test.cc',
      '../../src/backend/ebpf/cache/correlated_dns_event_consumer.cc',
    ),
    cache_dns_policy_src,
    dependencies: catch2_with_main_dep,
    include_directories: inc_src,
)

test('Correlated DNS Event Consumer Test', correlated_dns_event_consumer_test_exe)

ebpf_cache_verifier_bpf_obj = custom_target(
  'ebpf_cache_verifier.bpf.o',
  input: 'backend/ebpf_cache_verifier.bpf.c',
  output: 'ebpf_cache_verifier.bpf.o',
  depends: vmlinux_h,
  depend_files: files(
    '../../src/include/ebpf_cache_abi.h',
    '../../src/include/ebpf_cache_fingerprint.h',
    '../../src/bpf/arena/bpf_arena_common.h',
  ),
  command: [
    clang, '-g', '-O2', '-target', 'bpf',
    '-D__BPF__=1',
    '-I' + meson.project_build_root(),
    '-I' + meson.project_source_root() + '/src/include',
    '-I' + meson.project_source_root() + '/src',
    '-c', '@INPUT@', '-o', '@OUTPUT@'
  ]
)

ebpf_cache_verifier_skel = custom_target(
  'ebpf_cache_verifier.skel.h',
  input: ebpf_cache_verifier_bpf_obj,
  output: 'ebpf_cache_verifier.skel.h',
  command: [bpftool, 'gen', 'skeleton', '@INPUT@'],
  capture: true
)

ebpf_cache_verifier_test_exe = executable(
    'ebpf_cache_verifier_test',
    files(
      'backend/ebpf_cache_verifier_test.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_map.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_storage_layout.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_store.cc',
    ),
    ebpf_cache_verifier_skel,
    dependencies: [libbpf_dep, dependency('threads')],
    include_directories: inc_src,
    override_options: ['b_sanitize=none'],
)

test('eBPF Cache Verifier Gate', ebpf_cache_verifier_test_exe)

ebpf_production_verifier_test_exe = executable(
    'ebpf_production_verifier_test',
    files(
      'backend/ebpf_production_verifier_test.cc',
      '../../src/backend/ebpf/cache/ebpf_cache_storage_layout.cc',
    ),
    bpf_skel,
    dependencies: libbpf_dep,
    include_directories: inc_src,
    override_options: ['b_sanitize=none'],
)

test('eBPF Production Verifier Gate', ebpf_production_verifier_test_exe)

# ====================
# C++ CLI Parser Test
# ====================
cli_parser_test_exe = executable(
    'cli_parser_test',
    'cli/cli_test.cc',
    files(
      '../../src/cli/cli.cc',
    ),
    dependencies: [argparse_dep, catch2_with_main_dep],
    include_directories: inc_src,
)

test('CLI Parser Test', cli_parser_test_exe)

# ====================
# C++ Process Control Test
# ====================
process_control_test_exe = executable(
    'process_control_test',
    'process_control/process_control_test.cc',
    process_control_src,
    dependencies: catch2_with_main_dep,
    include_directories: inc_src,
)

test('Process Control Test', process_control_test_exe)

# ====================
# C++ Backend Runner Test
# ====================
backend_runner_test_exe = executable(
    'backend_runner_test',
    'backend/backend_runner_test.cc',
    backend_src,
    dependencies: catch2_with_main_dep,
    include_directories: inc_src,
)

test('Backend Runner Test', backend_runner_test_exe)

# ====================
# C++ eBPF Backend Test
# ====================
ebpf_backend_test_exe = executable(
    'ebpf_backend_test',
    files(
      'backend/ebpf_backend_test.cc',
      'backend/fake_ebpf_native_session_test.cc',
    ),
    backend_src,
    cache_dns_policy_src,
    ebpf_backend_src,
    bpf_skel,
    dependencies: [catch2_with_main_dep, libbpf_dep, libcap_dep],
    include_directories: inc_src,
    c_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
    cpp_args: (bpf_log ? ['-DSHINKU_BPF_LOG_ENABLED=1'] : ['-DSHINKU_BPF_LOG_ENABLED=0']),
)

test('eBPF Backend Test', ebpf_backend_test_exe)
