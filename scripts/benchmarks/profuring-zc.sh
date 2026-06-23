#!/usr/bin/env bash
# io_uring SendMsgZc zero-copy profiling.
#
# The profiling baseline (docs/profiling/baseline-2026-07.md) shows 15% CPU
# overhead from __kmalloc (skb allocation) in the kernel UDP send path.
# SendMsgZc eliminates this by reusing the user-space buffer directly.
#
# This script profiles the ZC path vs the standard SendMsg path to measure
# the skb allocation reduction. It requires:
#   - Kernel 6.0+ for stable SendMsgZc
#   - io_uring feature enabled: cargo build --release --features io_uring
#   - Root access for perf record
#
# Usage:
#   sudo ./profiling-zc.sh [DURATION_SEC]
#   DURATION_SEC defaults to 30

set -euo pipefail

DURATION="${1:-30}"

PROJECT_ROOT="/root/QuicFuscate-git"
BINARY="$PROJECT_ROOT/target/release/quicfuscate"
HARNESS="$PROJECT_ROOT/target/release/harness"
OUTPUT_DIR="$PROJECT_ROOT/docs/profiling"
FLAMEGRAPH_PL="/tmp/FlameGraph/flamegraph.pl"
STACKCOLLAPSE="/tmp/FlameGraph/stackcollapse-perf.pl"

mkdir -p "$OUTPUT_DIR"

generate_flamegraph() {
    local perf_data="$1"
    local output_svg="$2"
    local title="$3"
    perf script -i "$perf_data" 2>/dev/null | \
        "$STACKCOLLAPSE" 2>/dev/null | \
        "$FLAMEGRAPH_PL" --title "$title" --width 1200 > "$output_svg" 2>/dev/null
    echo "  Flamegraph: $(ls -la "$output_svg" 2>/dev/null | awk '{print $5}') bytes"
}

check_zc_support() {
    echo "Checking SendMsgZc kernel support..."
    # Kernel 6.0+ required for stable SendMsgZc
    local kver=$(uname -r | cut -d. -f1)
    if [[ "$kver" -lt 6 ]]; then
        echo "WARNING: Kernel $(uname -r) < 6.0 — SendMsgZc may not be stable"
        echo "  SendMsgZc requires kernel 6.0+ for stability"
    else
        echo "  Kernel $(uname -r) — SendMsgZc should be supported"
    fi
}

run_harness_zc_scenario() {
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

echo "=== io_uring SendMsgZc Zero-Copy Profiling ==="
echo "Server: broderick (aarch64, Ubuntu 24.04, 4 cores, 23 GB RAM)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Duration per scenario: ${DURATION}s"
echo ""

check_zc_support

# Scenario m: Large payload ZC (1200B — typical 1-RTT, ZC should eliminate skb alloc)
run_harness_zc_scenario "m" "io_uring ZC (1200B, batch=32)" 1200 32 50000

# Scenario n: Small payload ZC (256B — FEC repair packets, ZC impact on small pkts)
run_harness_zc_scenario "n" "io_uring ZC (256B, batch=64)" 256 64 50000

# Scenario o: Large batch ZC (1200B, batch=128 — max batch, ZC amortization)
run_harness_zc_scenario "o" "io_uring ZC (1200B, batch=128)" 1200 128 20000

echo ""
echo "=== ZC Profiling Complete ==="
echo ""
echo "Analysis steps:"
echo "  1. Compare flamegraph-m.svg vs flamegraph-a.svg (baseline)"
echo "     — Look for __kmalloc reduction in the ZC flamegraph"
echo "     — ZC should eliminate the 15% skb allocation overhead"
echo "  2. Check telemetry: curl localhost:9091/metrics | grep io_uring_zc"
echo "     — quicfuscate_io_uring_zc_sends_total should be > 0"
echo "     — quicfuscate_io_uring_zc_notifs_total should be > 0"
echo "  3. Compare throughput: ZC vs non-ZC (if kernel supports both)"
echo ""
echo "Flamegraphs:"
ls -la "$OUTPUT_DIR"/flamegraph-{m,n,o}.svg 2>/dev/null
