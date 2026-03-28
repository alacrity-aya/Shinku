# Configuration
build_dir := "build"
test_dir := "test"
ns := "dns-ns"
uv := shell("which uv")

# Default behavior: List all available commands
default:
    @just --list

# ============================================================================
# C/BPF Build Commands (Meson)
# ============================================================================

# Compile the project (meson compile)
build: 
    meson compile -C {{build_dir}}

# Clean the build directory
clean:
    rm -rf {{build_dir}}

# Config the build directory
config:
    meson setup {{build_dir}} --reconfigure
    

# ============================================================================
# Python Network Testing Commands (Requires sudo)
# Note: All commands change into the test/ directory first to ensure uv finds pyproject.toml
# ============================================================================

# Create network topology (Netns + Veth)
net-up:
    cd {{test_dir}} && sudo {{uv}} run topology.py setup

# Tear down network topology
net-down:
    cd {{test_dir}} && sudo {{uv}} run topology.py teardown

# Send DNS packets
# Usage: 
#    just send                (default to google.com)
#    just send -d baidu.com   (specify domain)
#    just send -t TXT         (specify type)
#    just send -v 100         (specify VLAN)
#    just send -d test.com -v 20 (combine arguments)
send *args:
    #!/usr/bin/env bash
    # Uses a bash script to handle argument forwarding:
    # 1. cd test/ : Ensure correct uv environment
    # 2. sudo ip netns exec : Enter network namespace
    # 3. uv run sender.py : Run the packet sender script
    
    cd {{test_dir}} && \
    sudo ip netns exec {{ns}} \
    {{uv}} run sender.py {{args}}

# Debug: Enter the Netns shell environment
net-shell:
    sudo ip netns exec {{ns}} bash

# ============================================================================
# Static Analysis Commands
# ============================================================================

# Run clang-tidy static analysis
tidy:
    ./scripts/run-clang-tidy.sh

# Run clang-tidy with auto-fix
tidy-fix:
    ./scripts/run-clang-tidy.sh --fix

# Run clang-format on all source files
fmt:
    find src -name "*.c" -o -name "*.h" | xargs clang-format -i

# ============================================================================
# Observability Commands (Prometheus + Grafana)
# ============================================================================

# Start Prometheus + Grafana stack
obs-up:
    ./observability/up.sh

# Stop Prometheus + Grafana stack
obs-down:
    ./observability/down.sh

# ============================================================================
# Sanitizer Test Commands
# ============================================================================

# Run AddressSanitizer tests
asan-test:
    meson setup build-asan --reconfigure -Db_sanitize=address
    meson compile -C build-asan
    meson test -C build-asan

# Run ThreadSanitizer tests
tsan-test:
    meson setup build-tsan --reconfigure -Db_sanitize=thread
    meson compile -C build-tsan
    meson test -C build-tsan

# Build optimized benchmark binary (no sanitizers)
bench-build:
    meson setup build-bench --reconfigure -Dbuildtype=release -Db_sanitize=none -Dbuild_benchmark_bin=true
    meson compile -C build-bench shinku_bench
