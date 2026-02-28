#!/usr/bin/env bash
# DNS Cache Benchmark: Measures real-world performance improvement of eBPF XDP DNS cache
# Compares: dnsperf → Unbound (baseline) vs dnsperf → dns-cache → Unbound (with XDP cache)
#
# Requirements: unbound, dnsperf, sudo
# Usage: sudo bash tests/benchmark/run_benchmark.sh

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$PROJECT_ROOT/tests/benchmark"
RESULTS_DIR="$BENCH_DIR/results"
QUERY_FILE="$BENCH_DIR/queries.txt"

NS_NAME="dns-ns"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
IP_HOST="10.99.0.1"
IP_NS="10.99.0.2"
DNS_PORT=53

UNBOUND_CONF="/tmp/unbound-bench.conf"
UNBOUND_PID=""
DNS_CACHE_PID=""

# dnsperf parameters
DNSPERF_CLIENTS=10        # concurrent clients
DNSPERF_DURATION=10       # seconds per test
DNSPERF_WARMUP_RUNS=2     # warmup passes through the query file
DNSPERF_MAX_QPS=0         # 0 = unlimited

# ─── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
hdr()  { echo -e "\n${CYAN}═══════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}\n"; }

# ─── Cleanup ─────────────────────────────────────────────────────────────
cleanup() {
    log "Cleaning up..."

    # Kill dns-cache
    if [[ -n "${DNS_CACHE_PID:-}" ]] && kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        kill "$DNS_CACHE_PID" 2>/dev/null || true
        wait "$DNS_CACHE_PID" 2>/dev/null || true
        ok "dns-cache stopped"
    fi

    # Kill unbound
    if [[ -n "${UNBOUND_PID:-}" ]] && kill -0 "$UNBOUND_PID" 2>/dev/null; then
        kill "$UNBOUND_PID" 2>/dev/null || true
        wait "$UNBOUND_PID" 2>/dev/null || true
        ok "Unbound stopped"
    fi
    # Also try pidfile
    if [[ -f /tmp/unbound-bench.pid ]]; then
        kill "$(cat /tmp/unbound-bench.pid)" 2>/dev/null || true
        rm -f /tmp/unbound-bench.pid
    fi

    # Detach XDP from veth-host (dns-cache attaches it)
    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true

    # Detach TC from veth-host
    tc qdisc del dev "$VETH_HOST" clsact 2>/dev/null || true

    # Tear down topology
    python3 "$PROJECT_ROOT/tests/integration/topology.py" teardown 2>/dev/null || true

    # Remove temp files
    rm -f "$UNBOUND_CONF" /tmp/unbound-bench.pid

    log "Cleanup complete"
}
trap cleanup EXIT

# ─── Prerequisite Checks ────────────────────────────────────────────────
check_prereqs() {
    local missing=0
    for cmd in unbound dnsperf ip tc python3; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing: $cmd"
            missing=1
        fi
    done

    if [[ ! -x "$PROJECT_ROOT/build/dns-cache" ]]; then
        err "dns-cache binary not found. Run: meson compile -C build dns-cache"
        missing=1
    fi
    if [[ ! -f "$PROJECT_ROOT/build/xdp_pass.bpf.o" ]]; then
        err "xdp_pass.bpf.o not found. Run: meson compile -C build xdp_pass.bpf.o"
        missing=1
    fi

    if [[ $EUID -ne 0 ]]; then
        err "Must run as root (need netns, XDP, unbound)"
        missing=1
    fi

    [[ $missing -eq 1 ]] && exit 1
    ok "All prerequisites met"
}

# ─── Generate Query File ────────────────────────────────────────────────
generate_queries() {
    log "Generating query file..."
    mkdir -p "$BENCH_DIR"

    # Popular domains — realistic workload with high repetition (cacheable)
    # dnsperf format: <domain> <type>
    cat > "$QUERY_FILE" <<'EOF'
google.com A
www.google.com A
facebook.com A
www.facebook.com A
amazon.com A
www.amazon.com A
apple.com A
www.apple.com A
microsoft.com A
www.microsoft.com A
cloudflare.com A
www.cloudflare.com A
github.com A
www.github.com A
stackoverflow.com A
www.stackoverflow.com A
wikipedia.org A
www.wikipedia.org A
youtube.com A
www.youtube.com A
twitter.com A
netflix.com A
linkedin.com A
reddit.com A
instagram.com A
yahoo.com A
bing.com A
zoom.us A
slack.com A
discord.com A
google.com AAAA
facebook.com AAAA
amazon.com AAAA
cloudflare.com AAAA
github.com AAAA
EOF

    local count
    count=$(wc -l < "$QUERY_FILE")
    ok "Generated $count queries in $QUERY_FILE"
}

# ─── Setup Network Topology ─────────────────────────────────────────────
setup_topology() {
    log "Setting up network topology..."

    # Tear down any leftover state
    python3 "$PROJECT_ROOT/tests/integration/topology.py" teardown 2>/dev/null || true
    sleep 0.5

    python3 "$PROJECT_ROOT/tests/integration/topology.py" setup
    if [[ $? -ne 0 ]]; then
        err "Failed to set up topology"
        exit 1
    fi

    # Verify connectivity
    if ip netns exec "$NS_NAME" ping -c 1 -W 1 "$IP_HOST" &>/dev/null; then
        ok "Topology ready — $IP_NS ↔ $IP_HOST connectivity confirmed"
    else
        err "Topology connectivity check failed"
        exit 1
    fi
}

# ─── Configure and Start Unbound ────────────────────────────────────────
start_unbound() {
    log "Configuring Unbound..."

    # Stop system unbound if running
    systemctl stop unbound 2>/dev/null || true

    # Create minimal config: listen on veth-host IP, forward to upstream
    cat > "$UNBOUND_CONF" <<EOF
server:
    interface: ${IP_HOST}
    port: ${DNS_PORT}
    access-control: 10.99.0.0/24 allow
    do-daemonize: no
    use-syslog: no
    logfile: ""
    verbosity: 0
    num-threads: 2
    msg-cache-size: 64m
    rrset-cache-size: 128m
    cache-min-ttl: 300
    cache-max-ttl: 86400
    prefetch: yes
    # Disable DNSSEC for benchmark simplicity
    val-permissive-mode: yes
    # Reduce latency
    so-reuseport: yes
    outgoing-range: 8192
    num-queries-per-thread: 4096

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
EOF

    log "Starting Unbound on ${IP_HOST}:${DNS_PORT}..."
    unbound -c "$UNBOUND_CONF" &
    UNBOUND_PID=$!
    sleep 1

    if ! kill -0 "$UNBOUND_PID" 2>/dev/null; then
        err "Unbound failed to start"
        # Try to see why
        unbound-checkconf "$UNBOUND_CONF" 2>&1 || true
        exit 1
    fi

    # Verify it responds
    if ip netns exec "$NS_NAME" dig +short +time=3 +tries=1 @"$IP_HOST" google.com A &>/dev/null; then
        ok "Unbound responding on ${IP_HOST}:${DNS_PORT}"
    else
        warn "Unbound may not be fully ready yet, continuing..."
    fi
}

# ─── Run dnsperf ─────────────────────────────────────────────────────────
run_dnsperf() {
    local label="$1"
    local outfile="$2"
    local duration="${3:-$DNSPERF_DURATION}"
    local clients="${4:-$DNSPERF_CLIENTS}"

    log "Running dnsperf: ${label} (${duration}s, ${clients} clients)..."

    ip netns exec "$NS_NAME" dnsperf \
        -s "$IP_HOST" \
        -p "$DNS_PORT" \
        -d "$QUERY_FILE" \
        -l "$duration" \
        -c "$clients" \
        -t 5 \
        -S 1 \
        2>&1 | tee "$outfile"

    ok "dnsperf completed: $label → $outfile"
}

# ─── Extract Metrics from dnsperf output ─────────────────────────────────
extract_metrics() {
    local outfile="$1"
    # Extract key lines
    grep -E "(Queries sent|Queries completed|Queries lost|Run time|Queries per second|Average Latency|Latency StdDev|Minimum Latency|Maximum Latency)" "$outfile" || true
}

# ─── Start dns-cache ─────────────────────────────────────────────────────
start_dns_cache() {
    log "Starting dns-cache on ${VETH_HOST}..."

    "$PROJECT_ROOT/build/dns-cache" -i "$VETH_HOST" -l info &
    DNS_CACHE_PID=$!
    sleep 2

    if ! kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        err "dns-cache failed to start"
        exit 1
    fi

    ok "dns-cache running (PID: $DNS_CACHE_PID)"
}

stop_dns_cache() {
    if [[ -n "${DNS_CACHE_PID:-}" ]] && kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        kill "$DNS_CACHE_PID" 2>/dev/null || true
        wait "$DNS_CACHE_PID" 2>/dev/null || true
        DNS_CACHE_PID=""

        # Detach XDP and TC
        ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
        tc qdisc del dev "$VETH_HOST" clsact 2>/dev/null || true

        ok "dns-cache stopped and BPF programs detached"
    fi
}

# ─── Warmup Phase ────────────────────────────────────────────────────────
warmup_cache() {
    log "Warming up cache (${DNSPERF_WARMUP_RUNS} passes)..."

    ip netns exec "$NS_NAME" dnsperf \
        -s "$IP_HOST" \
        -p "$DNS_PORT" \
        -d "$QUERY_FILE" \
        -n "$DNSPERF_WARMUP_RUNS" \
        -c 1 \
        -t 5 \
        > /dev/null 2>&1

    # Give userspace time to process ring buffer events and populate cache
    sleep 2
    ok "Cache warmed up"
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

main() {
    hdr "DNS Cache Performance Benchmark"

    check_prereqs
    generate_queries
    mkdir -p "$RESULTS_DIR"

    # ── Phase 1: Setup ──
    hdr "Phase 1: Environment Setup"
    setup_topology
    start_unbound

    # ── Phase 2: Baseline (no dns-cache) ──
    hdr "Phase 2: Baseline — Unbound Only (no XDP cache)"
    log "Warming up Unbound cache..."
    ip netns exec "$NS_NAME" dnsperf \
        -s "$IP_HOST" -p "$DNS_PORT" -d "$QUERY_FILE" \
        -n 3 -c 1 -t 5 > /dev/null 2>&1
    sleep 1

    run_dnsperf "baseline" "$RESULTS_DIR/baseline.txt"
    echo
    log "Baseline metrics:"
    extract_metrics "$RESULTS_DIR/baseline.txt"

    # ── Phase 3: With dns-cache ──
    hdr "Phase 3: With dns-cache (XDP fast path)"
    start_dns_cache

    warmup_cache

    run_dnsperf "with-cache" "$RESULTS_DIR/with-cache.txt"
    echo
    log "With-cache metrics:"
    extract_metrics "$RESULTS_DIR/with-cache.txt"

    stop_dns_cache

    # ── Phase 4: Compare ──
    hdr "Phase 4: Results Comparison"
    echo
    echo "────────────────────────────────────────"
    echo "  BASELINE (Unbound only)"
    echo "────────────────────────────────────────"
    extract_metrics "$RESULTS_DIR/baseline.txt"
    echo
    echo "────────────────────────────────────────"
    echo "  WITH DNS-CACHE (XDP fast path)"
    echo "────────────────────────────────────────"
    extract_metrics "$RESULTS_DIR/with-cache.txt"
    echo

    # Extract QPS numbers for comparison
    local baseline_qps with_cache_qps
    baseline_qps=$(grep "Queries per second" "$RESULTS_DIR/baseline.txt" | awk '{print $NF}' | head -1)
    with_cache_qps=$(grep "Queries per second" "$RESULTS_DIR/with-cache.txt" | awk '{print $NF}' | head -1)

    if [[ -n "$baseline_qps" && -n "$with_cache_qps" ]]; then
        local speedup
        speedup=$(echo "scale=2; $with_cache_qps / $baseline_qps" | bc 2>/dev/null || echo "N/A")
        echo "────────────────────────────────────────"
        echo -e "  ${GREEN}SPEEDUP: ${speedup}x${NC}"
        echo -e "  Baseline QPS:   $baseline_qps"
        echo -e "  With Cache QPS: $with_cache_qps"
        echo "────────────────────────────────────────"
    fi

    # Extract latency for comparison
    local baseline_lat with_cache_lat
    baseline_lat=$(grep "Average Latency" "$RESULTS_DIR/baseline.txt" | awk '{print $(NF-1)}' | head -1)
    with_cache_lat=$(grep "Average Latency" "$RESULTS_DIR/with-cache.txt" | awk '{print $(NF-1)}' | head -1)

    if [[ -n "$baseline_lat" && -n "$with_cache_lat" ]]; then
        local lat_reduction
        lat_reduction=$(echo "scale=2; (1 - $with_cache_lat / $baseline_lat) * 100" | bc 2>/dev/null || echo "N/A")
        echo -e "  Baseline Avg Latency:   ${baseline_lat}s"
        echo -e "  With Cache Avg Latency: ${with_cache_lat}s"
        echo -e "  ${GREEN}Latency Reduction: ${lat_reduction}%${NC}"
        echo "────────────────────────────────────────"
    fi

    hdr "Benchmark Complete"
    log "Raw results saved to: $RESULTS_DIR/"
}

main "$@"
