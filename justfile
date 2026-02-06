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

# Configure/Reset the build directory (meson setup --reconfigure)
config:
    meson setup {{build_dir}} --reconfigure

# Clean the build directory
clean:
    rm -rf {{build_dir}}

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
