#!/usr/bin/env bash
# Description: Full profiling baseline — 6 scenarios on broderick (loopback).
# Uses harness udp-throughput for UDP fast path + client/server for QUIC connection.
set -euo pipefail

PROJECT_ROOT="/root/QuicFuscate-git"
BINARY="$PROJECT_ROOT/target/release/quicfuscate"
HARNESS="$PROJECT_ROOT/target/release/harness"
OUTPUT_DIR="$PROJECT_ROOT/docs/profiling"
FLAMEGRAPH_PL="/tmp/FlameGraph/flamegraph.pl"
STACKCOLLAPSE="/tmp/FlameGraph/stackcollapse-perf.pl"

mkdir -p "$OUTPUT_DIR"

CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"

DURATION=30  # seconds per scenario

generate_flamegraph() {
    local perf_data="$1"
    local output_svg="$2"
    local title="$3"
    perf script -i "$perf_data" 2>/dev/null | \
        "$STACKCOLLAPSE" 2>/dev/null | \
        "$FLAMEGRAPH_PL" --title "$title" --width 1200 > "$output_svg" 2>/dev/null
    echo "  Flamegraph: $(ls -la "$output_svg" 2>/dev/null | awk '{print $5}') bytes"
}

run_harness_scenario() {
    local label="$1"
    local title="$2"
    local size="${3:-1200}"
    local batch="${4:-32}"
    local iters="${5:-50000}"
    local perf_data="$OUTPUT_DIR/perf-${label}.data"
    local svg="$OUTPUT_DIR/flamegraph-${label}.svg"
    local csv="$OUTPUT_DIR/scenario-${label}.csv"

    echo ""
    echo "=== Scenario $label: $title ==="
    echo "  size=${size}B batch=$batch iters=$iters"

    "$HARNESS" udp-throughput --size "$size" --iters "$iters" --batch "$batch" > "/tmp/harness-${label}.log" 2>&1 &
    local hpid=$!
    sleep 1
    perf record -F 99 -g -p "$hpid" -o "$perf_data" -- sleep "$DURATION" 2>&1 | tail -3
    wait "$hpid" 2>/dev/null || true

    local result
    result=$(cat "/tmp/harness-${label}.log" | tail -1)
    echo "  Result: $result"

    generate_flamegraph "$perf_data" "$svg" "$title"
    echo "scenario,label,size,batch,iters,result" > "$csv"
    echo "$label,$label,$size,$batch,$iters,$result" >> "$csv"

    rm -f "$perf_data"
}

run_connection_scenario() {
    local label="$1"
    local title="$2"
    local fec_mode="${3:-off}"
    local stealth_mode="${4:-off}"
    local perf_data="$OUTPUT_DIR/perf-${label}.data"
    local svg_server="$OUTPUT_DIR/flamegraph-${label}-server.svg"
    local svg_client="$OUTPUT_DIR/flamegraph-${label}-client.svg"
    local csv="$OUTPUT_DIR/scenario-${label}.csv"

    echo ""
    echo "=== Scenario $label: $title ==="
    echo "  FEC=$fec_mode  Stealth=$stealth_mode"

    # Start server
    "$BINARY" server --cert "$CERT" --key "$KEY" --listen 127.0.0.1:4433 \
        --fec-mode "$fec_mode" -v > "/tmp/server-${label}.log" 2>&1 &
    local spid=$!
    sleep 2

    # Start client
    "$BINARY" client --remote 127.0.0.1:4433 --fec-mode "$fec_mode" -v > "/tmp/client-${label}.log" 2>&1 &
    local cpid=$!
    sleep 2

    # Record perf on server
    echo "  Recording server perf for ${DURATION}s..."
    perf record -F 99 -g -p "$spid" -o "$perf_data" -- sleep "$DURATION" 2>&1 | tail -3

    # Extract stats
    local rtt=$(grep -oE 'RTT [0-9]+ ms' "/tmp/client-${label}.log" | tail -1 || echo "N/A")
    local loss=$(grep -oE 'Loss [0-9.]+%' "/tmp/client-${label}.log" | tail -1 || echo "N/A")

    echo "  Stats: $rtt  $loss"

    generate_flamegraph "$perf_data" "$svg_server" "$title (Server)"
    echo "scenario,label,fec_mode,stealth_mode,rtt,loss" > "$csv"
    echo "$label,$label,$fec_mode,$stealth_mode,$rtt,$loss" >> "$csv"

    # Cleanup
    kill "$cpid" 2>/dev/null || true
    kill "$spid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    rm -f "$perf_data"
    sleep 1
}

echo "=== QuicFuscate Profiling Baseline ==="
echo "Server: broderick (aarch64, Ubuntu 24.04, 4 cores, 23 GB RAM)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Duration per scenario: ${DURATION}s"
echo ""

# Scenario a: Pure throughput (harness, no QUIC overhead)
run_harness_scenario "a" "Pure UDP Throughput (FEC off, stealth off)" 1200 32 50000

# Scenario b: Small packet throughput (simulates FEC Normal overhead)
run_harness_scenario "b" "UDP Throughput Small Packets (FEC Normal sim)" 256 64 50000

# Scenario c: Large batch throughput (simulates FEC Extreme overhead)
run_harness_scenario "c" "UDP Throughput Large Batch (FEC Extreme sim)" 1200 128 20000

# Scenario d: QUIC connection — FEC off, stealth off
run_connection_scenario "d" "QUIC Connection (FEC off, stealth off)" off off

# Scenario e: QUIC connection — FEC auto, stealth off
run_connection_scenario "e" "QUIC Connection (FEC auto, stealth off)" auto off

# Scenario f: QUIC connection — FEC auto, stealth performance
run_connection_scenario "f" "QUIC Connection (FEC auto, stealth performance)" auto performance

echo ""
echo "=== Profiling Baseline Complete ==="
echo ""
echo "CSV files:"
ls -la "$OUTPUT_DIR"/scenario-*.csv 2>/dev/null
echo ""
echo "Flamegraphs:"
ls -la "$OUTPUT_DIR"/flamegraph-*.svg 2>/dev/null
