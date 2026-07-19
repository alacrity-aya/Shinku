#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BENCH_DIR="$PROJECT_ROOT/tests/benchmark"
RESULTS_DIR="$BENCH_DIR/results"
SCENARIO_DIR="$RESULTS_DIR/scenarios"

NS_NAME="dns-ns"
VETH_HOST="veth-host"
IP_HOST="10.99.0.1"
DNS_PORT=53

UNBOUND_CONF="/tmp/unbound-bench.conf"
UNBOUND_PID=""
DNS_CACHE_PID=""
DNS_CACHE_LOG=""

DNSPERF_DURATION="${DNSPERF_DURATION:-10}"
DNSPERF_CLIENTS="${DNSPERF_CLIENTS:-10}"
DNSPERF_TIMEOUT="${DNSPERF_TIMEOUT:-5}"
DNSPERF_THREADS="${DNSPERF_THREADS:-1}"

HOT_QUERY_FILE="$SCENARIO_DIR/queries.hot.txt"
MIXED_QUERY_FILE="$SCENARIO_DIR/queries.mixed.txt"
UNIQUE_QUERY_FILE="$SCENARIO_DIR/queries.unique.txt"
NEGATIVE_QUERY_FILE="$SCENARIO_DIR/queries.negative.txt"
TTL_SHORT_QUERY_FILE="$SCENARIO_DIR/queries.ttlshort.txt"

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

cleanup() {
    log "Cleaning up benchmark environment..."

    if [[ -n "${DNS_CACHE_PID:-}" ]] && kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        kill "$DNS_CACHE_PID" 2>/dev/null || true
        wait "$DNS_CACHE_PID" 2>/dev/null || true
    fi

    if [[ -n "${UNBOUND_PID:-}" ]] && kill -0 "$UNBOUND_PID" 2>/dev/null; then
        kill "$UNBOUND_PID" 2>/dev/null || true
        wait "$UNBOUND_PID" 2>/dev/null || true
    fi

    if [[ -f /tmp/unbound-bench.pid ]]; then
        kill "$(cat /tmp/unbound-bench.pid)" 2>/dev/null || true
        rm -f /tmp/unbound-bench.pid
    fi

    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    tc qdisc del dev "$VETH_HOST" clsact 2>/dev/null || true
    python3 "$PROJECT_ROOT/tests/integration/topology.py" teardown 2>/dev/null || true
    rm -f "$UNBOUND_CONF"

    log "Cleanup complete"
}
trap cleanup EXIT

check_prereqs() {
    local missing=0
    for cmd in unbound dnsperf ip tc python3 awk sed grep; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Missing required command: $cmd"
            missing=1
        fi
    done

    if [[ ! -x "$PROJECT_ROOT/build/shinku" ]]; then
        err "shinku binary missing: meson compile -C build shinku"
        missing=1
    fi

    if [[ ! -f "$PROJECT_ROOT/build/xdp_pass.bpf.o" ]]; then
        err "xdp_pass.bpf.o missing: meson compile -C build xdp_pass.bpf.o"
        missing=1
    fi

    if [[ $EUID -ne 0 ]]; then
        err "Must run as root"
        missing=1
    fi

    [[ $missing -eq 1 ]] && exit 1
    ok "All prerequisites satisfied"
}

setup_topology() {
    python3 "$PROJECT_ROOT/tests/integration/topology.py" teardown >/dev/null 2>&1 || true
    python3 "$PROJECT_ROOT/tests/integration/topology.py" setup
}

start_unbound() {
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
    cache-min-ttl: 2
    cache-max-ttl: 30
    prefetch: yes
    val-permissive-mode: yes
    so-reuseport: yes
    outgoing-range: 8192
    num-queries-per-thread: 4096

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
EOF

    systemctl stop unbound 2>/dev/null || true
    unbound -c "$UNBOUND_CONF" &
    UNBOUND_PID=$!
    sleep 1

    if ! kill -0 "$UNBOUND_PID" 2>/dev/null; then
        err "Unbound failed to start"
        exit 1
    fi
    ok "Unbound started"
}

gen_query_files() {
    mkdir -p "$SCENARIO_DIR"

    cat > "$HOT_QUERY_FILE" <<'EOF'
google.com A
www.google.com A
cloudflare.com A
github.com A
EOF

    cat > "$MIXED_QUERY_FILE" <<'EOF'
google.com A
google.com A
google.com A
www.google.com A
www.google.com A
cache-hit.example.com A
cache-hit.example.com A
unique-0001.example.com A
unique-0002.example.com A
unique-0003.example.com A
unique-0004.example.com A
unique-0005.example.com A
unique-0006.example.com A
unique-0007.example.com A
unique-0008.example.com A
unique-0009.example.com A
EOF

    : > "$UNIQUE_QUERY_FILE"
    local i
    for i in $(seq 1 1200); do
        printf "wrap-%05d.example.com A\n" "$i" >> "$UNIQUE_QUERY_FILE"
    done

    cat > "$NEGATIVE_QUERY_FILE" <<'EOF'
neg-nxdomain.example.com A
neg-nxdomain.example.com A
neg-nodata.example.com A
neg-nodata.example.com A
neg-no-soa.example.com A
neg-no-soa.example.com A
EOF

    cat > "$TTL_SHORT_QUERY_FILE" <<'EOF'
google.com A
www.cloudflare.com A
github.com A
EOF

    ok "Generated scenario query files"
}

start_dns_cache() {
    local scenario="$1"
    local arena_pages="$2"

    DNS_CACHE_LOG="$SCENARIO_DIR/${scenario}.shinku.log"
    local config_file="$SCENARIO_DIR/${scenario}.shinku.toml"

    {
        echo 'backend = "ebpf"'
        echo
        echo '[ebpf]'
        echo "iface = \"$VETH_HOST\""
        echo "arena_pages = $arena_pages"
        echo 'cleanup_interval = "10s"'
        echo
        echo '[cache]'
        echo 'max_entries = 16384'
        echo 'max_response_bytes = 512'
        echo 'cache_negative = true'
    } > "$config_file"

    "$PROJECT_ROOT/build/shinku" \
        run \
        --config "$config_file" \
        >"$DNS_CACHE_LOG" 2>&1 &

    DNS_CACHE_PID=$!
    sleep 2

    if ! kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        err "shinku failed to start for scenario $scenario"
        exit 1
    fi
}

stop_dns_cache() {
    if [[ -n "${DNS_CACHE_PID:-}" ]] && kill -0 "$DNS_CACHE_PID" 2>/dev/null; then
        kill "$DNS_CACHE_PID" 2>/dev/null || true
        wait "$DNS_CACHE_PID" 2>/dev/null || true
        DNS_CACHE_PID=""
    fi
    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    tc qdisc del dev "$VETH_HOST" clsact 2>/dev/null || true
}

parse_dnsperf_stat() {
    local file="$1"
    local key="$2"
    awk -F ':' -v k="$key" '$0 ~ k {gsub(/^ +| +$/, "", $2); print $2; exit}' "$file"
}

extract_latency_percentile() {
    local file="$1"
    local percentile="$2"
    awk -v p="$percentile" '$0 ~ p"%" {for(i=1;i<=NF;i++){if($i ~ /^[0-9.]+$/){v=$i}}} END{if(v=="") print "N/A"; else print v}' "$file"
}

run_dnsperf() {
    local query_file="$1"
    local outfile="$2"
    local duration="$3"
    local clients="$4"
    local threads="$5"

    ip netns exec "$NS_NAME" dnsperf \
        -s "$IP_HOST" \
        -p "$DNS_PORT" \
        -d "$query_file" \
        -l "$duration" \
        -c "$clients" \
        -T "$threads" \
        -t "$DNSPERF_TIMEOUT" \
        -S 1 \
        -O latency-histogram \
        2>&1 | tee "$outfile"
}

sample_process_resource() {
    local pid="$1"
    local out="$2"

    local cpu rss
    cpu=$(ps -p "$pid" -o %cpu= | awk '{print $1+0}')
    rss=$(ps -p "$pid" -o rss= | awk '{print $1+0}')

    echo "$cpu;$rss" > "$out"
}

print_scenario_report() {
    local scenario="$1"
    local dnsperf_out="$2"
    local resource="$3"
    local report_out="$4"

    local qps avg_lat run_time p95 p99 cpu rss
    qps=$(parse_dnsperf_stat "$dnsperf_out" "Queries per second")
    avg_lat=$(parse_dnsperf_stat "$dnsperf_out" "Average Latency")
    run_time=$(parse_dnsperf_stat "$dnsperf_out" "Run time")
    p95=$(extract_latency_percentile "$dnsperf_out" "95")
    p99=$(extract_latency_percentile "$dnsperf_out" "99")

    cpu=$(awk -F ';' '{print $1}' "$resource")
    rss=$(awk -F ';' '{print $2}' "$resource")

    {
        echo "scenario=$scenario"
        echo "qps=$qps"
        echo "run_time=$run_time"
        echo "avg_latency_line=$avg_lat"
        echo "p95_latency_s=$p95"
        echo "p99_latency_s=$p99"
        echo "cpu_percent=$cpu"
        echo "rss_kb=$rss"
    } > "$report_out"
}

run_scenario() {
    local scenario="$1"
    local query_file="$2"
    local duration="$3"
    local clients="$4"
    local threads="$5"
    local arena_pages="$6"
    local warmup_runs="$7"
    local note="$8"

    hdr "Scenario: $scenario"
    log "$note"

    local out_prefix="$SCENARIO_DIR/$scenario"
    local dnsperf_out="$out_prefix.dnsperf.txt"
    local resource="$out_prefix.resource.txt"
    local report="$out_prefix.report.txt"

    start_dns_cache "$scenario" "$arena_pages"

    if [[ "$warmup_runs" -gt 0 ]]; then
        ip netns exec "$NS_NAME" dnsperf \
            -s "$IP_HOST" -p "$DNS_PORT" -d "$query_file" -n "$warmup_runs" -c 1 -t "$DNSPERF_TIMEOUT" \
            > /dev/null 2>&1
        sleep 1
    fi

    run_dnsperf "$query_file" "$dnsperf_out" "$duration" "$clients" "$threads"
    sample_process_resource "$DNS_CACHE_PID" "$resource"
    print_scenario_report "$scenario" "$dnsperf_out" "$resource" "$report"

    ok "Scenario complete: $scenario"
    stop_dns_cache
}

run_baseline() {
    hdr "Scenario: baseline-unbound"
    local out="$SCENARIO_DIR/baseline-unbound.dnsperf.txt"
    run_dnsperf "$HOT_QUERY_FILE" "$out" "$DNSPERF_DURATION" "$DNSPERF_CLIENTS" "$DNSPERF_THREADS"
    ok "Scenario complete: baseline-unbound"
}

run_ttl_expiry_probe() {
    hdr "TTL Expiry Probe"

    local probe_out="$SCENARIO_DIR/ttl-expiry.probe.txt"
    start_dns_cache "ttl-expiry-probe" 2112

    ip netns exec "$NS_NAME" python3 "$PROJECT_ROOT/tests/integration/dns_client.py" "google.com" "0a01" "$IP_HOST" "3" > "$probe_out" 2>&1 || true
    sleep 2
    ip netns exec "$NS_NAME" python3 "$PROJECT_ROOT/tests/integration/dns_client.py" "google.com" "0a02" "$IP_HOST" "3" >> "$probe_out" 2>&1 || true

    sleep 3
    ip netns exec "$NS_NAME" python3 "$PROJECT_ROOT/tests/integration/dns_client.py" "google.com" "0a03" "$IP_HOST" "3" >> "$probe_out" 2>&1 || true

    stop_dns_cache
    ok "TTL expiry probe complete"
}

print_final_summary() {
    hdr "Benchmark Suite Summary"
    local report
    for report in "$SCENARIO_DIR"/*.report.txt; do
        [[ -f "$report" ]] || continue
        local scenario qps p99 cpu rss
        scenario=$(grep '^scenario=' "$report" | cut -d '=' -f2)
        qps=$(grep '^qps=' "$report" | cut -d '=' -f2)
        p99=$(grep '^p99_latency_s=' "$report" | cut -d '=' -f2)
        cpu=$(grep '^cpu_percent=' "$report" | cut -d '=' -f2)
        rss=$(grep '^rss_kb=' "$report" | cut -d '=' -f2)

        echo "[$scenario] QPS=$qps p99=${p99}s cpu=${cpu}% rss=${rss}KB"
    done

    echo
    log "Detailed outputs saved under: $SCENARIO_DIR"
}

main() {
    hdr "Shinku Extended Benchmark Suite"
    check_prereqs
    mkdir -p "$RESULTS_DIR" "$SCENARIO_DIR"
    setup_topology
    start_unbound
    gen_query_files

    run_baseline

    run_scenario \
        "hot-cache" \
        "$HOT_QUERY_FILE" \
        "$DNSPERF_DURATION" \
        "$DNSPERF_CLIENTS" \
        "$DNSPERF_THREADS" \
        2112 \
        3 \
        "High-hit workload for cache fast-path"

    run_scenario \
        "mixed-hit" \
        "$MIXED_QUERY_FILE" \
        "$DNSPERF_DURATION" \
        "$DNSPERF_CLIENTS" \
        "$DNSPERF_THREADS" \
        2112 \
        1 \
        "Mixed hit/miss workload"

    run_scenario \
        "high-concurrency" \
        "$MIXED_QUERY_FILE" \
        "$DNSPERF_DURATION" \
        64 \
        4 \
        2112 \
        1 \
        "Stress test with high client and thread counts"

    run_scenario \
        "negative-cache" \
        "$NEGATIVE_QUERY_FILE" \
        8 \
        8 \
        1 \
        2112 \
        1 \
        "NXDOMAIN/NODATA/no-SOA negative-cache behavior"

    run_scenario \
        "wraparound-pressure" \
        "$UNIQUE_QUERY_FILE" \
        12 \
        16 \
        2 \
        2112 \
        0 \
        "Force cache-map wraparound pressure with many unique keys"

    run_ttl_expiry_probe
    print_final_summary
}

main "$@"
