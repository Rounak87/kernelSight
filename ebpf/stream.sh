#!/bin/bash
# ==============================================================================
# Stream eBPF telemetry from EC2 to your local ingestion pipeline
# ==============================================================================

# Default ngrok endpoint
DEFAULT_ENDPOINT="https://friction-spool-frostlike.ngrok-free.dev/ingest"

ENDPOINT="${1:-$DEFAULT_ENDPOINT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "  Kernel AIOps Telemetry Streamer"
echo "  Target URL : $ENDPOINT"
echo "  Interval   : 1 second"
echo "======================================================================"

sudo python3 "${SCRIPT_DIR}/collector.py" --endpoint "$ENDPOINT" --interval 1
