#!/usr/bin/env bash
# TUN-mode profiling with data transfer + tc-netem simulation.
#
# The original profiling baseline (profiling-baseline.sh) only captured idle
# QUIC connections — the real data plane (FEC, AEAD, stealth shaping, H3
# framing) was never profiled under load. This script fills that gap:
#
# 1. Configures tc-netem on loopback for loss/latency simulation
# 2. Starts server + client with TUN-mode enabled
# 3. Runs iperf3 through the tunnel for real data transfer
# 4. Records perf on the server during active data transfer
# 5. Generates flamegraphs for the data-plane hot path
#
# Requirements (broderick):
#   - Root access
#   - Rust release build: cargo build --release --bin quicfuscate
#   - FlameGraph repo cloned to /tmp/FlameGraph
#   - iperf3 installed: apt install iperf3
#   - TUN module loaded: modprobe tun
#
# Usage:
#   sudo ./profiling-tun-mode.sh [DURATION_SEC]
#   DURATION_SEC defaults to 30

set -euo pipefail

DURATION="${1:-30}"

PROJECT_ROOT="/root/QuicFuscate-git"
BINARY="$PROJECT_ROOT/target/release/quicfuscate"
OUTPUT_DIR="$PROJECT_ROOT/docs/profiling"
FLAMEGRAPH_PL="/tmp/FlameGraph/flamegraph.pl"
STACKCOLLAPSE="/tmp/FlameGraph/stackcollapse-perf.pl"

CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"

mkdir -p "$OUTPUT_DIR"

# TUN IP configuration
SERVER_TUN_IP="10.0.1.1"
CLIENT_TUN_IP="10.0.1.2"
TUN_NETMASK="255.255.255.0"

# tc-netem parameters (adjust per scenario)
NETEM_DELAY="50ms"
NETEM_LOSS="5%"

generate_flamegraph() {
    local perf_data="$1"
    local output_svg="$2"
    local title="$3"
    perf script -i "$perf_data" 2>/dev/null | \
        "$STACKCOLLAPSE" 2>/dev/null | \
        "$FLAMEGRAPH_PL" --title "$title" --width 1200 > "$output_svg" 2>/dev/null
    echo "  Flamegraph: $(ls -la "$output_svg" 2>/dev/null | awk '{print $5}') bytes"
}

setup_netem() {
    echo "Configuring tc-netem on loopback: delay=${NETEM_DELAY} loss=${NETEM_LOSS}"
    tc qdisc add dev lo root netem delay "$NETEM_DELAY" loss "$NETEM_LOSS" 2>/dev/null || true
}

teardown_netem() {
    echo "Removing tc-netem from loopback..."
    tc qdisc del dev lo root 2>/dev/null || true
}

run_tun_scenario() {
    local label="$1"
    local title="$2"
    local fec_mode="${3:-auto}"
    local netem_delay="${4:-0ms}"
    local netem_loss="${5:-0%}"
    local perf_data="$OUTPUT_DIR/perf-${label}.data"
    local svg="$OUTPUT_DIR/flamegraph-${label}.svg"
    local csv="$OUTPUT_DIR/scenario-${label}.csv"

    echo ""
    echo "=== Scenario $label: $title ==="
    echo "  FEC=$fec_mode  Netem: delay=$netem_delay loss=$netem_loss"

    # Configure netem for this scenario
    NETEM_DELAY="$netem_delay"
    NETEM_LOSS="$netem_loss"
    if [[ "$netem_delay" != "0ms" || "$netem_loss" != "0%" ]]; then
        setup_netem
    fi

    # Start server with TUN
    "$BINARY" server --cert "$CERT" --key "$KEY" --listen 127.0.0.1:4433 \
        --fec-mode "$fec_mode" \
        --tun --tun-ip "$SERVER_TUN_IP" --tun-netmask "$TUN_NETMASK" \
        -v > "/tmp/server-${label}.log" 2>&1 &
    local spid=$!
    sleep 2

    # Start client with TUN
    "$BINARY" client --remote 127.0.0.1:4433 --fec-mode "$fec_mode" \
        --tun --tun-ip "$CLIENT_TUN_IP" --tun-netmask "$TUN_NETMASK" \
        -v > "/tmp/client-${label}.log" 2>&1 &
    local cpid=$!
    sleep 3

    # Start iperf3 server on the client TUN IP
    iperf3 -s -B "$CLIENT_TUN_IP" -D > "/tmp/iperf3-server-${label}.log" 2>&1 || true
    sleep 1

    # Run iperf3 client through the tunnel (from server TUN IP to client TUN IP)
    echo "  Running iperf3 through tunnel for ${DURATION}s..."
    iperf3 -c "$CLIENT_TUN_IP" -t "$DURATION" -P 4 > "/tmp/iperf3-client-${label}.log" 2>&1 &
    local iperf_pid=$!

    # Record perf on the server during active data transfer
    echo "  Recording server perf for ${DURATION}s..."
    perf record -F 99 -g -p "$spid" -o "$perf_data" -- sleep "$DURATION" 2>&1 | tail -3

    wait "$iperf_pid" 2>/dev/null || true

    # Extract results
    local throughput=$(grep -oE '[0-9.]+ Mbits/sec' "/tmp/iperf3-client-${label}.log" | tail -1 || echo "N/A")
    local rtt=$(grep -oE 'RTT [0-9]+ ms' "/tmp/client-${label}.log" | tail -1 || echo "N/A")
    local loss=$(grep -oE 'Loss [0-9.]+%' "/tmp/client-${label}.log" | tail -1 || echo "N/A")

    echo "  Throughput: $throughput"
    echo "  Stats: $rtt  $loss"

    generate_flamegraph "$perf_data" "$svg" "$title (Server, TUN mode)"
    echo "scenario,label,fec_mode,netem_delay,netem_loss,throughput,rtt,loss" > "$csv"
    echo "$label,$label,$fec_mode,$netem_delay,$netem_loss,$throughput,$rtt,$loss" >> "$csv"

    # Cleanup
    iperf3 -s -B "$CLIENT_TUN_IP" -k 2>/dev/null || true
    kill "$cpid" 2>/dev/null || true
    kill "$spid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    rm -f "$perf_data"

    if [[ "$netem_delay" != "0ms" || "$netem_loss" != "0%" ]]; then
        teardown_netem
    fi
    sleep 1
}

# Trap to ensure netem is always cleaned up
trap teardown_netem EXIT

echo "=== QuicFuscate TUN-mode Profiling ==="
echo "Server: broderick (aarch64, Ubuntu 24.04, 4 cores, 23 GB RAM)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Duration per scenario: ${DURATION}s"
echo ""

# Scenario g: TUN mode, no loss, no delay — baseline data plane
run_tun_scenario "g" "TUN Data Plane (FEC auto, no loss)" auto 0ms 0%

# Scenario h: TUN mode with 50ms delay — latency stress
run_tun_scenario "h" "TUN Data Plane (FEC auto, 50ms delay)" auto 50ms 0%

# Scenario i: TUN mode with 5% loss — FEC stress (activates FEC encode/decode)
run_tun_scenario "i" "TUN Data Plane (FEC auto, 5% loss)" auto 0ms 5%

# Scenario j: TUN mode with 50ms delay + 5% loss — combined stress
run_tun_scenario "j" "TUN Data Plane (FEC auto, 50ms+5% loss)" auto 50ms 5%

# Scenario k: TUN mode with FEC off + 5% loss — FEC impact comparison
run_tun_scenario "k" "TUN Data Plane (FEC off, 5% loss)" off 0ms 5%

echo ""
echo "=== TUN-mode Profiling Complete ==="
echo ""
echo "CSV files:"
ls -la "$OUTPUT_DIR"/scenario-{g,h,i,j,k}.csv 2>/dev/null
echo ""
echo "Flamegraphs:"
ls -la "$OUTPUT_DIR"/flamegraph-{g,h,i,j,k}.svg 2>/dev/null
echo ""
echo "Next steps:"
echo "  1. Compare throughput: FEC on vs off (scenarios i vs k)"
echo "  2. Identify data-plane hotspots in flamegraphs (should show FEC/AEAD)"
echo "  3. Use results to gate Phase 4 micro-optimizations (TODO-390..401)"
