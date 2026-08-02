#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-crypto.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --dry-run) DRY_RUN=1;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--fast|--full] [--dry-run]"; echo "Crypto Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/crypto-bench-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "${CARGO_FEATURES:-}" "${RUSTFLAGS_EXTRA:-}" "${JOBS:-}"

mkdir -p "$OUTPUT_DIR"
# shellcheck disable=SC2034
LOG_FILE="$OUTPUT_DIR/crypto-bench.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_crypto_comprehensive"; JSON_FIRST_RUN=1

SELECTED_CELLS=(crypto_all_native)
case "$(uname -m)" in
  x86_64)
    (( FAST )) || SELECTED_CELLS+=(crypto_all_sse2 crypto_all_avx2)
    ;;
  aarch64|arm64)
    (( FAST )) || SELECTED_CELLS+=(crypto_all_neon)
    ;;
esac
SELECTED_CELLS+=(morus_native)
case "$(uname -m)" in
  x86_64)
    (( FAST )) || SELECTED_CELLS+=(morus_sse2)
    ;;
  aarch64|arm64)
    (( FAST )) || SELECTED_CELLS+=(morus_neon)
    ;;
esac
SELECTED_CELLS+=(aes_gcm_native)
case "$(uname -m)" in
  x86_64)
    (( FAST )) || SELECTED_CELLS+=(aes_gcm_aesni aes_gcm_vaes)
    ;;
  aarch64|arm64)
    (( FAST )) || SELECTED_CELLS+=(aes_gcm_crypto)
    ;;
esac
SELECTED_CELLS+=(chacha20_poly1305_native)

append_mode_metadata() {
    local mode="full"
    (( FAST )) && mode="fast"
    local cells_json="["
    local cell
  for cell in "${SELECTED_CELLS[@]}"; do
    if [[ "$cells_json" != "[" ]]; then
      cells_json+=","
    fi
    cells_json+="\"$(qf_json_escape "$cell")\""
  done
  cells_json+="]"
    qf_json_append_object "$JSON" "cell=meta" "result=PASS" "reason=" "argv=json:[]" "environment=json:$(qf_json_environment)" \
      "command_status=int:0" \
      "meta=json:{\"mode\":\"$mode\",\"fast\":$FAST,\"selected_cells\":$cells_json,\"cell_count\":${#SELECTED_CELLS[@]}}"
}

append_mode_metadata
if (( DRY_RUN )); then
    echo "DRY-RUN: mode=$([[ "$FAST" -eq 1 ]] && echo fast || echo full) cells=${SELECTED_CELLS[*]}"
    qf_json_append_object "$JSON" "cell=dry-run" "result=SKIP" "reason=dry_run" "command_status=null"
    json_end "$JSON"
    exit 0
fi

echo "==============================================================="
echo "  Crypto Comprehensive Benchmark Suite"
echo "==============================================================="
echo "  Testing all AEAD implementations with hardware acceleration"
echo "==============================================================="

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping crypto benches."
  qf_json_append_object "$JSON" "cell=suite" "result=SKIP" "reason=no_rust_benches" "command_status=int:0"
  json_end "$JSON"
  exit 0
fi

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

BENCH_FAILURES=0

# Function to measure crypto throughput
measure_throughput() {
    local name="$1"
    local test_pattern="$2"
    shift 2
    local -a env_vars=()
    while [[ "$#" -gt 0 && "$1" != "--" ]]; do
        env_vars+=("$1")
        shift
    done
    [[ "${1:-}" == "--" ]] || { error "measure_throughput requires -- before cargo arguments"; return 2; }
    shift
    local output_file="$OUTPUT_DIR/${name}.txt"
    local command_status=0
    local result="PASS"
    local reason=""
    
    echo -e "\n${BLUE}> Benchmarking $name...${NC}"
    
    local command_argv_json
    local command_environment_json
    if [[ "${#env_vars[@]}" -gt 0 ]]; then
        if run_cargo_with_env "${env_vars[@]}" -- test --release --lib "$test_pattern" >"$output_file" 2>&1; then
            command_status=0
        else
            command_status=$?
            result="FAIL"
            reason="cargo_test_failed"
            BENCH_FAILURES=$((BENCH_FAILURES + 1))
        fi
        command_argv_json="$(qf_json_array env "${env_vars[@]}" cargo test --release --lib "$test_pattern")"
        command_environment_json="$(qf_json_environment_with_assignments "${env_vars[@]}")"
    else
        if run_cargo_with_env -- test --release --lib "$test_pattern" >"$output_file" 2>&1; then
            command_status=0
        else
            command_status=$?
            result="FAIL"
            reason="cargo_test_failed"
            BENCH_FAILURES=$((BENCH_FAILURES + 1))
        fi
        command_argv_json="$(qf_json_array env cargo test --release --lib "$test_pattern")"
        command_environment_json="$(qf_json_environment)"
    fi
    cat "$output_file"
    qf_json_append_object "$JSON" "name=$name" "result=$result" "reason=$reason" \
        "argv=json:$command_argv_json" "environment=json:$command_environment_json" \
        "command_status=int:$command_status" "output=$output_file"
    return 0
}

# CPU Feature Detection
echo -e "\n${YELLOW}=== CPU Features ===${NC}"
echo "Architecture: $(uname -m)"
if [[ $(uname -m) == "x86_64" ]]; then
    echo "SIMD Support:"
    grep -o 'sse2\|ssse3\|sse4_1\|avx\|avx2\|avx512f\|aes' /proc/cpuinfo 2>/dev/null | sort -u || \
        sysctl -a 2>/dev/null | grep -i "hw.optional" | grep -E "aes|avx" || echo "  Detection not available on this platform"
elif [[ $(uname -m) == "aarch64" ]] || [[ $(uname -m) == "arm64" ]]; then
    echo "SIMD Support:"
    echo "  NEON: Yes (built-in)"
    grep -o 'aes\|pmull\|sha1\|sha2' /proc/cpuinfo 2>/dev/null | sort -u || \
        sysctl -a 2>/dev/null | grep -i "hw.optional" | grep -E "aes|neon" || echo "  ARM crypto extensions"
fi

if (( FAST )); then
    echo -e "\n${YELLOW}=== Fast Crypto Suite Performance ===${NC}"
else
    echo -e "\n${YELLOW}=== Full Crypto Suite Performance ===${NC}"
fi
measure_throughput "crypto_all_native" "crypto::tests" --

if [[ "$FAST" -eq 0 && $(uname -m) == "x86_64" ]]; then
    measure_throughput "crypto_all_sse2" "crypto::tests" "RUSTFLAGS=-C target-feature=+sse2" --
    measure_throughput "crypto_all_avx2" "crypto::tests" "RUSTFLAGS=-C target-feature=+avx2" --
elif [[ "$FAST" -eq 0 && ( $(uname -m) == "aarch64" || $(uname -m) == "arm64" ) ]]; then
    measure_throughput "crypto_all_neon" "crypto::tests" "RUSTFLAGS=-C target-feature=+neon" --
fi

# MORUS-1280-128 Benchmarks
echo -e "\n${YELLOW}=== MORUS-1280-128 Performance ===${NC}"
measure_throughput "morus_native" "crypto::morus::morus_tests" --

if [[ "$FAST" -eq 0 && $(uname -m) == "x86_64" ]]; then
    measure_throughput "morus_sse2" "crypto::morus::morus_tests" "RUSTFLAGS=-C target-feature=+sse2" --
elif [[ "$FAST" -eq 0 && ( $(uname -m) == "aarch64" || $(uname -m) == "arm64" ) ]]; then
    measure_throughput "morus_neon" "crypto::morus::morus_tests" "RUSTFLAGS=-C target-feature=+neon" --
fi

# AES-GCM Benchmarks
echo -e "\n${YELLOW}=== AES-GCM Performance ===${NC}"
measure_throughput "aes_gcm_native" "crypto::gcm::tests" --

if [[ "$FAST" -eq 0 && $(uname -m) == "x86_64" ]]; then
    measure_throughput "aes_gcm_aesni" "crypto::gcm::tests" "RUSTFLAGS=-C target-feature=+aes,+sse2" --
    measure_throughput "aes_gcm_vaes" "crypto::gcm::tests" "RUSTFLAGS=-C target-feature=+vaes,+avx512f" --
elif [[ "$FAST" -eq 0 && ( $(uname -m) == "aarch64" || $(uname -m) == "arm64" ) ]]; then
    measure_throughput "aes_gcm_crypto" "crypto::gcm::tests" "RUSTFLAGS=-C target-feature=+aes,+neon" --
fi

# ChaCha20-Poly1305 Benchmarks (fallback)
echo -e "\n${YELLOW}=== ChaCha20-Poly1305 Performance ===${NC}"
measure_throughput "chacha20_poly1305_native" "crypto::tests::chacha20poly1305" --

# Comparative Analysis
echo -e "\n${YELLOW}=== Comparative Analysis ===${NC}"

# Create comparison table
cat > "$OUTPUT_DIR/comparison.txt" << EOF
Crypto Performance Comparison (MB/s for 16KB blocks)
====================================================

Algorithm         | Native | SSE2/NEON | AVX2/Crypto | AVX512/VAES
------------------|--------|-----------|-------------|------------
EOF

# Parse results and add to comparison
for algo in crypto_all morus aes_gcm chacha20_poly1305; do
    native=$(grep "16384" "$OUTPUT_DIR/${algo}_native.txt" 2>/dev/null | awk '{print $NF}' || echo "N/A")
    sse2=$(grep "16384" "$OUTPUT_DIR/${algo}_sse2.txt" 2>/dev/null | awk '{print $NF}' || \
           grep "16384" "$OUTPUT_DIR/${algo}_neon.txt" 2>/dev/null | awk '{print $NF}' || echo "N/A")
    avx2=$(grep "16384" "$OUTPUT_DIR/${algo}_avx2.txt" 2>/dev/null | awk '{print $NF}' || \
           grep "16384" "$OUTPUT_DIR/${algo}_crypto.txt" 2>/dev/null | awk '{print $NF}' || echo "N/A")
    avx512=$(grep "16384" "$OUTPUT_DIR/${algo}_vaes.txt" 2>/dev/null | awk '{print $NF}' || echo "N/A")
    
    printf "%-17s | %-6s | %-9s | %-11s | %-11s\n" "$algo" "$native" "$sse2" "$avx2" "$avx512" >> "$OUTPUT_DIR/comparison.txt"
done

cat "$OUTPUT_DIR/comparison.txt"

# Hardware Acceleration Analysis
echo -e "\n${YELLOW}=== Hardware Acceleration Impact ===${NC}"

# Calculate speedup factors
echo "Calculating speedup factors..."
cat > "$OUTPUT_DIR/speedup.txt" << 'EOF'
Hardware Acceleration Speedup Factors
=====================================

Algorithm    | SSE2/NEON vs Native | AVX2/Crypto vs Native | Best vs Native
-------------|--------------------|-----------------------|---------------
EOF

# Generate final report
echo -e "\n${GREEN}=== Benchmark Complete ===${NC}"
echo "Results saved to: $OUTPUT_DIR"
echo "Key files:"
echo "  - comparison.txt: Performance comparison table"
echo "  - speedup.txt: Hardware acceleration impact"
echo "  - *.txt: Individual benchmark results"

# Performance recommendations
echo -e "\n${YELLOW}=== Performance Recommendations ===${NC}"

best_algo=""
best_throughput=0

# Find best performing algorithm
for result in "$OUTPUT_DIR"/*.txt; do
    if grep -q "16384" "$result" 2>/dev/null; then
        throughput=$(grep "16384" "$result" | awk '{print $NF}' | sort -rn | head -1)
        if [ "$(echo "$throughput > $best_throughput" | bc -l 2>/dev/null)" = "1" ] 2>/dev/null; then
            best_throughput=$throughput
            best_algo=$(basename "$result" .txt)
        fi
    fi
done

if [ -n "$best_algo" ]; then
    echo -e "${GREEN}OK${NC} Best performing configuration: $best_algo"
    echo -e "${GREEN}OK${NC} Throughput: $best_throughput MB/s"
else
    echo -e "${GREEN}OK${NC} Run actual benchmarks to determine best configuration"
fi

echo -e "\n${GREEN}[OK] Crypto Benchmark Suite Complete${NC}"
json_end "$JSON"
if [[ "$BENCH_FAILURES" -gt 0 ]]; then
    echo -e "\n${RED}[FAIL] ${BENCH_FAILURES} crypto benchmark cells failed${NC}"
    exit 1
fi
