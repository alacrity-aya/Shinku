#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NS_NAME="dns-ns"
VETH_HOST="veth-host"
TOPOLOGY="$PROJECT_ROOT/tests/integration/topology.py"
DNS_CLIENT="$PROJECT_ROOT/tests/integration/dns_client.py"
SHINKU_BIN="${SHINKU_BIN:-$PROJECT_ROOT/build/shinku}"

SOAK_DURATION_SEC="${SOAK_DURATION_SEC:-300}"
SAMPLE_INTERVAL_SEC="${SAMPLE_INTERVAL_SEC:-30}"
METRICS_PORT="${METRICS_PORT:-9095}"
HOST_DNS_PORT="${HOST_DNS_PORT:-1053}"

CONTAINER_NAME="shinku-soak-unbound"
UNBOUND_IMAGE="${UNBOUND_IMAGE:-mvance/unbound:latest}"
UNBOUND_CONF_DIR="$PROJECT_ROOT/tests/soak/unbound"
RESULTS_DIR="$PROJECT_ROOT/tests/soak/results"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RESULTS_DIR/$RUN_ID"
UNBOUND_LOG_DIR="$RUN_DIR/unbound-logs"

SHINKU_PID=""
TOTAL_QUERIES=0
SUCCESS_QUERIES=0
TIMEOUT_QUERIES=0
RCODE_NONZERO_QUERIES=0
ANOMALY_COUNT=0
PREV_HIT=-1
PREV_MISS=-1
PREV_REJECT=-1
PREV_RING_DROP=-1
PREV_DEGRADED_TRANSITIONS=-1
ANOMALY_FILE=""
SUMMARY_FILE=""

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
err() { echo "[-] $*"; }

cleanup() {
    set +e
    log "Cleaning up soak environment..."

    if [[ -n "${SHINKU_PID:-}" ]] && kill -0 "$SHINKU_PID" 2>/dev/null; then
        kill "$SHINKU_PID" 2>/dev/null || true
        wait "$SHINKU_PID" 2>/dev/null || true
    fi

    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p udp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" >/dev/null 2>&1 || true

    ip link set dev "$VETH_HOST" xdp off >/dev/null 2>&1 || true
    tc qdisc del dev "$VETH_HOST" clsact >/dev/null 2>&1 || true
    python3 "$TOPOLOGY" teardown >/dev/null 2>&1 || true

    log "Cleanup complete"
}
trap cleanup EXIT

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || { err "Missing command: $cmd"; exit 1; }
}

metric_from_blob() {
    local blob="$1"
    local metric="$2"
    awk -v m="$metric" '$1==m {print $2; found=1} END{if(!found) print 0}' <<<"$blob"
}

record_anomaly() {
    local now="$1"
    local kind="$2"
    local msg="$3"
    ANOMALY_COUNT=$((ANOMALY_COUNT + 1))
    echo "$now kind=$kind $msg" >> "$ANOMALY_FILE"
}

probe_query() {
    local now="$1"
    local traffic_file="$2"
    local domain="$3"
    local txid="$4"

    TOTAL_QUERIES=$((TOTAL_QUERIES + 1))

    local out
    if ! out=$(ip netns exec "$NS_NAME" python3 "$DNS_CLIENT" "$domain" "$txid" "10.99.0.1" "2" 2>/dev/null); then
        TIMEOUT_QUERIES=$((TIMEOUT_QUERIES + 1))
        record_anomaly "$now" "query_timeout" "domain=$domain"
        echo "$now domain=$domain outcome=timeout" >> "$traffic_file"
        return 0
    fi

    if [[ -z "$out" || "$out" == "TIMEOUT" ]]; then
        TIMEOUT_QUERIES=$((TIMEOUT_QUERIES + 1))
        record_anomaly "$now" "query_timeout" "domain=$domain"
        echo "$now domain=$domain outcome=timeout" >> "$traffic_file"
        return 0
    fi

    local resp_hex rtt_us
    resp_hex=$(awk '{print $1}' <<<"$out")
    rtt_us=$(awk '{print $2}' <<<"$out")

    if [[ ${#resp_hex} -lt 24 ]]; then
        record_anomaly "$now" "short_response" "domain=$domain bytes_hex_len=${#resp_hex}"
        echo "$now domain=$domain outcome=short_response rtt_us=${rtt_us:-0}" >> "$traffic_file"
        return 0
    fi

    local flags_hex flags qr rcode
    flags_hex=${resp_hex:4:4}
    flags=$((16#$flags_hex))
    qr=$(((flags >> 15) & 0x1))
    rcode=$((flags & 0xF))

    if [[ $qr -ne 1 ]]; then
        record_anomaly "$now" "non_response" "domain=$domain qr=$qr"
    fi
    if [[ $rcode -ne 0 ]]; then
        RCODE_NONZERO_QUERIES=$((RCODE_NONZERO_QUERIES + 1))
        record_anomaly "$now" "rcode_nonzero" "domain=$domain rcode=$rcode"
    fi

    SUCCESS_QUERIES=$((SUCCESS_QUERIES + 1))
    echo "$now domain=$domain outcome=ok rtt_us=${rtt_us:-0} rcode=$rcode qr=$qr" >> "$traffic_file"
    return 0
}

check_prereqs() {
    require_cmd docker
    require_cmd python3
    require_cmd ip
    require_cmd iptables
    require_cmd curl

    if [[ $EUID -ne 0 ]]; then
        err "Must run as root"
        exit 1
    fi

    if [[ ! -x "$SHINKU_BIN" ]]; then
        err "Missing shinku binary: $SHINKU_BIN"
        exit 1
    fi

    mkdir -p "$RUN_DIR" "$UNBOUND_LOG_DIR"
    ok "Prerequisites OK"
}

setup_topology() {
    python3 "$TOPOLOGY" teardown >/dev/null 2>&1 || true
    python3 "$TOPOLOGY" setup
}

start_unbound_docker() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p udp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -i "$VETH_HOST" -p tcp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" >/dev/null 2>&1 || true

    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "${HOST_DNS_PORT}:53/udp" \
        -p "${HOST_DNS_PORT}:53/tcp" \
        -v "$UNBOUND_CONF_DIR/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro" \
        -v "$UNBOUND_LOG_DIR:/opt/unbound/etc/unbound/log" \
        "$UNBOUND_IMAGE" >/dev/null

    sleep 2
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        err "Unbound container failed to start"
        docker logs "$CONTAINER_NAME" || true
        exit 1
    fi

    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p udp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT"
    iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT"

    ok "Unbound container running"
}

wait_unbound_ready() {
    local tries=20
    local i
    for i in $(seq 1 "$tries"); do
        if ip netns exec "$NS_NAME" python3 "$DNS_CLIENT" "cloudflare.com" "0abc" "10.99.0.1" "2" >/dev/null 2>&1; then
            ok "Unbound became reachable from namespace"
            return 0
        fi
        sleep 1
    done

    err "Unbound did not become reachable from namespace"
    docker logs "$CONTAINER_NAME" || true
    exit 1
}

start_shinku() {
    "$SHINKU_BIN" -i "$VETH_HOST" -m "$METRICS_PORT" -l info >"$RUN_DIR/shinku.log" 2>&1 &
    SHINKU_PID=$!

    sleep 2
    if ! kill -0 "$SHINKU_PID" 2>/dev/null; then
        err "Shinku failed to start"
        exit 1
    fi
    ok "Shinku started"
}

soak_loop() {
    local end_ts
    end_ts=$(( $(date +%s) + SOAK_DURATION_SEC ))

    local metrics_file="$RUN_DIR/metrics.timeseries.prom"
    local health_file="$RUN_DIR/health.timeseries.log"
    local traffic_file="$RUN_DIR/traffic.timeseries.log"
    ANOMALY_FILE="$RUN_DIR/anomalies.log"
    SUMMARY_FILE="$RUN_DIR/summary.txt"

    echo "# run_id=$RUN_ID" > "$metrics_file"
    echo "# sample_interval_sec=$SAMPLE_INTERVAL_SEC" >> "$metrics_file"
    echo "# soak_duration_sec=$SOAK_DURATION_SEC" >> "$metrics_file"
    : > "$ANOMALY_FILE"
    : > "$SUMMARY_FILE"

    while [[ $(date +%s) -lt $end_ts ]]; do
        local now
        now=$(date -Is)

        probe_query "$now" "$traffic_file" "google.com" "1001"
        probe_query "$now" "$traffic_file" "github.com" "1002"
        probe_query "$now" "$traffic_file" "cloudflare.com" "1003"
        probe_query "$now" "$traffic_file" "nonexistent-subdomain-$RANDOM.example.com" "1004"

        local metrics_blob
        metrics_blob=$(curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" || true)
        {
            echo "# timestamp=$now"
            if [[ -n "$metrics_blob" ]]; then
                echo "$metrics_blob"
            else
                echo "# metrics_fetch_failed"
            fi
            echo
        } >> "$metrics_file"

        if [[ -z "$metrics_blob" ]]; then
            record_anomaly "$now" "metrics_fetch_failed" "endpoint=127.0.0.1:${METRICS_PORT}/metrics"
        else
            local hit miss reject ring_drop degraded_mode degraded_transitions
            hit=$(metric_from_blob "$metrics_blob" "shinku_cache_hit_total")
            miss=$(metric_from_blob "$metrics_blob" "shinku_cache_miss_total")
            reject=$(metric_from_blob "$metrics_blob" "shinku_parser_reject_total")
            ring_drop=$(metric_from_blob "$metrics_blob" "shinku_tc_ringbuf_drop_total")
            degraded_mode=$(metric_from_blob "$metrics_blob" "shinku_degraded_mode")
            degraded_transitions=$(metric_from_blob "$metrics_blob" "shinku_degraded_transitions_total")

            if [[ $PREV_HIT -ge 0 ]]; then
                local d_hit d_miss d_reject d_ring d_degraded
                d_hit=$((hit - PREV_HIT))
                d_miss=$((miss - PREV_MISS))
                d_reject=$((reject - PREV_REJECT))
                d_ring=$((ring_drop - PREV_RING_DROP))
                d_degraded=$((degraded_transitions - PREV_DEGRADED_TRANSITIONS))

                if [[ $d_reject -gt 0 ]]; then
                    record_anomaly "$now" "parser_reject_delta" "delta=$d_reject"
                fi
                if [[ $d_ring -gt 0 ]]; then
                    record_anomaly "$now" "ringbuf_drop_delta" "delta=$d_ring"
                fi
                if [[ $degraded_mode -gt 0 || $d_degraded -gt 0 ]]; then
                    record_anomaly "$now" "degraded_mode" "active=$degraded_mode transitions_delta=$d_degraded"
                fi

                local d_total
                d_total=$((d_hit + d_miss))
                if [[ $d_total -ge 8 ]]; then
                    local miss_pct
                    miss_pct=$(awk -v m="$d_miss" -v t="$d_total" 'BEGIN{if(t>0) printf "%.2f", (m*100.0)/t; else print "0.00"}')
                    if awk "BEGIN{exit !($miss_pct > 95.0)}"; then
                        record_anomaly "$now" "high_miss_ratio" "miss_pct=$miss_pct window_total=$d_total"
                    fi
                fi
            fi

            PREV_HIT=$hit
            PREV_MISS=$miss
            PREV_REJECT=$reject
            PREV_RING_DROP=$ring_drop
            PREV_DEGRADED_TRANSITIONS=$degraded_transitions
        fi

        local shinku_cpu shinku_rss unbound_cpu unbound_mem
        shinku_cpu=$(ps -p "$SHINKU_PID" -o %cpu= 2>/dev/null | awk '{print $1+0}')
        shinku_rss=$(ps -p "$SHINKU_PID" -o rss= 2>/dev/null | awk '{print $1+0}')

        unbound_cpu=$(docker stats --no-stream --format '{{.CPUPerc}}' "$CONTAINER_NAME" 2>/dev/null | tr -d '%')
        unbound_mem=$(docker stats --no-stream --format '{{.MemUsage}}' "$CONTAINER_NAME" 2>/dev/null)

        echo "$now shinku_cpu=${shinku_cpu:-0} shinku_rss_kb=${shinku_rss:-0} unbound_cpu=${unbound_cpu:-0} unbound_mem=${unbound_mem:-n/a}" >> "$health_file"
        echo "$now traffic=sampled_mixed" >> "$traffic_file"

        if ! kill -0 "$SHINKU_PID" 2>/dev/null; then
            err "Shinku exited during soak"
            return 1
        fi
        if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            err "Unbound container exited during soak"
            return 1
        fi

        sleep "$SAMPLE_INTERVAL_SEC"
    done

    local timeout_pct rcode_pct success_pct
    timeout_pct=$(awk -v t="$TIMEOUT_QUERIES" -v q="$TOTAL_QUERIES" 'BEGIN{if(q>0) printf "%.2f", (t*100.0)/q; else print "0.00"}')
    rcode_pct=$(awk -v r="$RCODE_NONZERO_QUERIES" -v q="$TOTAL_QUERIES" 'BEGIN{if(q>0) printf "%.2f", (r*100.0)/q; else print "0.00"}')
    success_pct=$(awk -v s="$SUCCESS_QUERIES" -v q="$TOTAL_QUERIES" 'BEGIN{if(q>0) printf "%.2f", (s*100.0)/q; else print "0.00"}')

    {
        echo "run_id=$RUN_ID"
        echo "duration_sec=$SOAK_DURATION_SEC"
        echo "sample_interval_sec=$SAMPLE_INTERVAL_SEC"
        echo "total_queries=$TOTAL_QUERIES"
        echo "success_queries=$SUCCESS_QUERIES"
        echo "timeout_queries=$TIMEOUT_QUERIES"
        echo "rcode_nonzero_queries=$RCODE_NONZERO_QUERIES"
        echo "success_pct=$success_pct"
        echo "timeout_pct=$timeout_pct"
        echo "rcode_nonzero_pct=$rcode_pct"
        echo "anomaly_count=$ANOMALY_COUNT"
    } > "$SUMMARY_FILE"

    if awk "BEGIN{exit !($timeout_pct > 5.0)}"; then
        record_anomaly "$(date -Is)" "timeout_ratio_high" "timeout_pct=$timeout_pct"
    fi

    return 0
}

main() {
    check_prereqs
    setup_topology
    start_unbound_docker
    wait_unbound_ready
    start_shinku

    log "Starting soak loop: duration=${SOAK_DURATION_SEC}s interval=${SAMPLE_INTERVAL_SEC}s"
    soak_loop

    ok "Soak completed. Results: $RUN_DIR"
}

main "$@"
