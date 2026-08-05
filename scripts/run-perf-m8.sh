#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dnsperf_version="2.15.0"
dnsperf_root="${DNSPERF_BUILD_ROOT:-/tmp/shinku-dnsperf-${dnsperf_version}}"
dnsperf_binary="${DNSPERF_JSON:-${dnsperf_root}/install/bin/dnsperf}"
mode="smoke"
canonical=0
extra_args=()

usage() {
    cat <<'EOF'
Usage: scripts/run-perf-m8.sh [--smoke|--full] [--canonical] [-- benchmark-options]

Default mode runs the short non-canonical smoke gate. The full mode runs the
five-round benchmark. --canonical requires a clean repository and leaves out
--allow-dirty; benchmark options after -- are forwarded unchanged.

Set DNSPERF_JSON to reuse an existing JSON-capable dnsperf binary.
EOF
}

while (($# > 0)); do
    case "$1" in
        --smoke)
            mode="smoke"
            shift
            ;;
        --full)
            mode="full"
            shift
            ;;
        --canonical)
            canonical=1
            mode="full"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            extra_args+=("$@")
            break
            ;;
        *)
            extra_args+=("$1")
            shift
            ;;
    esac
done

if [[ -n "${DNSPERF_JSON:-}" && ! -x "$dnsperf_binary" ]]; then
    printf 'DNSPERF_JSON is not an executable: %s\n' "$dnsperf_binary" >&2
    exit 2
fi

if [[ ! -x "$dnsperf_binary" ]]; then
    command -v curl >/dev/null || { printf 'curl is required to build dnsperf\n' >&2; exit 2; }
    command -v dnf >/dev/null || { printf 'dnf is required to install dnsperf build dependencies\n' >&2; exit 2; }

    if ! pkg-config --exists ck json-c ldns libnghttp2 openssl zlib 2>/dev/null; then
        sudo dnf install -y \
            gcc gcc-c++ make autoconf automake libtool pkgconf-pkg-config \
            ck-devel json-c-devel ldns-devel libnghttp2-devel openssl-devel zlib-devel
    fi

    archive="${dnsperf_root}/dnsperf-${dnsperf_version}.tar.gz"
    source_root="${dnsperf_root}/src"
    mkdir -p "$dnsperf_root"
    if [[ ! -f "$archive" ]]; then
        curl -L --fail --remove-on-error \
            "https://www.dns-oarc.net/files/dnsperf/dnsperf-${dnsperf_version}.tar.gz" \
            -o "$archive"
    fi
    if [[ ! -f "$source_root/configure.ac" ]]; then
        mkdir -p "$source_root"
        tar -xzf "$archive" --strip-components=1 -C "$source_root"
    fi

    cd "$source_root"
    if [[ ! -x ./configure ]]; then
        autoreconf -fi
    fi
    json_flag=()
    configure_help="$(./configure --help 2>&1)"
    if [[ "$configure_help" == *"--enable-json"* ]]; then
        json_flag+=(--enable-json)
    fi
    ./configure --prefix="${dnsperf_root}/install" "${json_flag[@]}"
    make -j"$(nproc)"
    make install
    dnsperf_binary="${dnsperf_root}/install/bin/dnsperf"
fi

test -x "$dnsperf_binary"
printf 'Using dnsperf: %s\n' "$dnsperf_binary"

cd "$project_root"
benchmark_args=(--dnsperf-binary "$dnsperf_binary")
if ((canonical == 0)); then
    benchmark_args+=(--allow-dirty)
fi
if [[ "$mode" == "smoke" ]]; then
    benchmark_args+=(--smoke)
fi
benchmark_args+=("${extra_args[@]}")

exec python3 tests/benchmark/run_perf_m8.py "${benchmark_args[@]}"
