cpp = meson.get_compiler('cpp')
if cpp.get_id() != 'clang'
  error('dns_fuzzing requires Clang and its compiler-rt libFuzzer runtime')
endif

dns_fuzz_args = [
  '-fsanitize=fuzzer,address,undefined',
  '-fno-omit-frame-pointer',
]

executable(
  'dns_wire_parser_fuzz',
  'dns_wire_parser_fuzz.cc',
  files(
    '../../src/cache/dns/wire_parser.cc',
  ),
  include_directories: inc_src,
  cpp_args: dns_fuzz_args,
  link_args: dns_fuzz_args,
  override_options: ['b_sanitize=none'],
  install: false,
)

executable(
  'dns_policy_fuzz',
  'dns_policy_fuzz.cc',
  cache_dns_policy_src,
  include_directories: inc_src,
  cpp_args: dns_fuzz_args,
  link_args: dns_fuzz_args,
  override_options: ['b_sanitize=none'],
  install: false,
)
