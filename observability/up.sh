#!/bin/bash
# Start Prometheus + Grafana for Shinku metrics visualization
# Usage: ./observability/up.sh [--build]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

docker compose up -d "$@"

echo ""
echo "=========================================="
echo "Observability stack started!"
echo "=========================================="
echo ""
echo "Prometheus:  http://localhost:9090"
echo "Grafana:     http://localhost:3000 (admin/admin)"
echo ""
echo "Shinku should expose metrics at: http://localhost:9095/metrics"
echo ""
echo "To stop: ./observability/down.sh"
echo ""
