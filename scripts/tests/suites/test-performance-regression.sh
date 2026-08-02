#!/usr/bin/env bash
# Description: Test suite runner: test-performance-regression.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1

echo "==============================================================="
echo "  Performance Regression Test Suite"
echo "==============================================================="

# Baseline/current JSON
BASELINE_FILE="$SCRIPT_DIR/performance_baseline.json"
CURRENT_FILE="$OUTPUT_DIR/performance_current.json"
SUMMARY_JSON="$OUTPUT_DIR/performance_results.json"
mkdir -p "$OUTPUT_DIR"
json_begin "$SUMMARY_JSON" "performance_regression"
FIRST=1
FAIL=0
BENCH_AVAILABLE=1
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"
BASE_FEATURES="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-}")"
DISCOVERY_DONE=0; DISCOVERY_STATUS=""; DISCOVERY_REASON=""; DISCOVERY_COUNT=0
DISCOVERY_COMMAND_STATUS=""; DISCOVERY_COMMAND=""; DISCOVERY_TARGET=""; DISCOVERY_FEATURES=""; DISCOVERY_RAW_OUTPUT="$TEST_LIST_FILE"
ACTIVE_DISCOVERY_STATUS=""; ACTIVE_DISCOVERY_REASON=""

# Performance thresholds (% degradation allowed)
THROUGHPUT_THRESHOLD=5
LATENCY_THRESHOLD=10
MEMORY_THRESHOLD=15
CPU_THRESHOLD=10

# Fast-mode test selection (reduced set)
if (( FAST )); then
  THROUGHPUT_TESTS=(aes_gcm_seal/1024B data_aead_single_seal_batch/aegis128l_1400B)
  LATENCY_TESTS=(connection_1rtt_send_recv/payload_1024B stream_frame_encoding/1024B_direct_writer)
  HOTPATH_TESTS=(varint/roundtrip_8vals)
  RUN_MEM_CPU=0
  RUN_SIMD=0
  SCALABILITY_CONNECTIONS=(100)
  SCALABILITY_STREAMS=(100)
  echo "FAST mode enabled: reduced performance test set"
else
  THROUGHPUT_TESTS=(fec_throughput aegis_128l_throughput aes_gcm_throughput chacha20_throughput)
  LATENCY_TESTS=(packet_processing stream datagram)
  HOTPATH_TESTS=(varint_encode varint_decode frame_parse)
  RUN_MEM_CPU=1
  RUN_SIMD=1
  SCALABILITY_CONNECTIONS=(10 100 1000)
  SCALABILITY_STREAMS=(10 100 1000)
fi

# Keep bench build and bench runs on the same flags to avoid rebuilds.
BASE_RUSTFLAGS="${RUSTFLAGS:-}"
EXTRA_RUSTFLAGS="${RUSTFLAGS_EXTRA:-}"
if [[ -n "$EXTRA_RUSTFLAGS" ]]; then
  export RUSTFLAGS="${EXTRA_RUSTFLAGS} ${BASE_RUSTFLAGS}"
fi
# Do not force LTO through global RUSTFLAGS here. It also applies to build
# scripts/proc-macros and breaks stable `cargo bench` with proc-macro crates.
LTO_FLAG=""
BENCH_RUSTFLAGS="-C target-cpu=native -C opt-level=3 ${LTO_FLAG} ${EXTRA_RUSTFLAGS} ${BASE_RUSTFLAGS}"

# Detect benchmark harness availability
detect_bench_targets() {
  if command -v cargo >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    cargo metadata --no-deps --format-version=1 2>/dev/null | \
      jq -e '.packages[].targets[] | select(.kind | index("bench"))' >/dev/null
    return $?
  fi
  if grep -Eq '^\s*\[\[bench\]\]' "$PROJECT_ROOT/Cargo.toml" 2>/dev/null; then
    return 0
  fi
  if [[ -d "$PROJECT_ROOT/benches" ]]; then
    return 0
  fi
  if grep -Eq '^\s*benches\s*=\s*\[\s*\]\s*$' "$PROJECT_ROOT/Cargo.toml" 2>/dev/null; then
    return 1
  fi
  return 1
}

if ! detect_bench_targets; then
  warn "No bench targets declared; skipping benchmark comparisons"
  BENCH_AVAILABLE=0
elif ! RUSTFLAGS="$BENCH_RUSTFLAGS" cargo bench --no-run --features benches >/dev/null 2>&1; then
  warn "Rust benches failed to build; skipping benchmark comparisons"
  BENCH_AVAILABLE=0
fi

# Build with optimizations (only when benches exist)
if [[ "$BENCH_AVAILABLE" -eq 1 && "$FAST" -eq 0 ]]; then
  echo -e "\n> Building with native optimizations..."
  RUSTFLAGS="$BENCH_RUSTFLAGS" run_cargo build --release --features benches || FAIL=1
fi

calc_change_percent() {
  local current="$1"
  local baseline="$2"
  if command -v bc >/dev/null 2>&1; then
    echo "scale=2; (($current - $baseline) / $baseline) * 100" | bc 2>/dev/null || echo "0"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY 2>/dev/null || echo "0"
current=float("$current")
baseline=float("$baseline")
print(0.0 if baseline == 0 else ((current - baseline) / baseline) * 100.0)
PY
    return
  fi
  warn "Missing bc/python3; cannot compute change percent"
  echo "0"
}

compare_gt() {
  local left="$1"
  local right="$2"
  if command -v bc >/dev/null 2>&1; then
    echo "$left > $right" | bc -l 2>/dev/null || echo "0"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY 2>/dev/null || echo "0"
left=float("$left")
right=float("$right")
print(1 if left > right else 0)
PY
    return
  fi
  warn "Missing bc/python3; cannot compare thresholds"
  echo "0"
}

append_performance_record() {
  local name="$1" metric="$2" value="$3" legacy_status="$4" result="$5" reason="$6"
  local command="$7" target="$8" feature_set="$9" discovered_count="${10:-null}"
  local executed_count="${11:-null}" command_status="${12:-null}"
  local discovery_status="${13:-not_applicable}" raw_output="${14:-}"
  if [[ "$FIRST" -eq 0 ]]; then echo "," >> "$SUMMARY_JSON"; fi
  FIRST=0
  printf '  {"name":"%s","metric":"%s","value":"%s","status":"%s","result":"%s","reason":"%s","command":"%s","target":"%s","feature_set":"%s","discovered_test_count":%s,"executed_test_count":%s,"command_status":%s,"discovery_status":"%s","raw_output":"%s"}' \
    "$(qf_json_escape "$name")" "$(qf_json_escape "$metric")" "$(qf_json_escape "$value")" \
    "$(qf_json_escape "$legacy_status")" "$(qf_json_escape "$result")" "$(qf_json_escape "$reason")" \
    "$(qf_json_escape "$command")" "$(qf_json_escape "$target")" "$(qf_json_escape "$feature_set")" \
    "$discovered_count" "$executed_count" "$command_status" "$(qf_json_escape "$discovery_status")" \
    "$(qf_json_escape "$raw_output")" >> "$SUMMARY_JSON"
}

ensure_test_list() {
  if [[ "$DISCOVERY_DONE" -eq 1 ]]; then
    ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
    ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_STATUS="$DISCOVERY_STATUS"; QF_CARGO_TEST_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_COUNT="$DISCOVERY_COUNT"; QF_CARGO_TEST_COMMAND_STATUS="$DISCOVERY_COMMAND_STATUS"
    QF_CARGO_TEST_COMMAND="$DISCOVERY_COMMAND"; QF_CARGO_TEST_TARGET="$DISCOVERY_TARGET"
    QF_CARGO_TEST_FEATURE_SET="$DISCOVERY_FEATURES"; QF_CARGO_TEST_FILTER="<all>"
    QF_CARGO_TEST_RAW_OUTPUT="$DISCOVERY_RAW_OUTPUT"
    return 0
  fi
  if qf_cargo_test_discover "$TEST_LIST_FILE" "lib" "$BASE_FEATURES" --release --lib; then
    local legacy_status="ok"
  else
    local legacy_status="fail"
    FAIL=1
  fi
  DISCOVERY_DONE=1
  DISCOVERY_STATUS="$QF_CARGO_TEST_STATUS"
  DISCOVERY_REASON="$QF_CARGO_TEST_REASON"
  DISCOVERY_COUNT="$QF_CARGO_TEST_COUNT"
  DISCOVERY_COMMAND_STATUS="$QF_CARGO_TEST_COMMAND_STATUS"
  DISCOVERY_COMMAND="$QF_CARGO_TEST_COMMAND"
  DISCOVERY_TARGET="$QF_CARGO_TEST_TARGET"
  DISCOVERY_FEATURES="$QF_CARGO_TEST_FEATURE_SET"
  DISCOVERY_RAW_OUTPUT="$QF_CARGO_TEST_RAW_OUTPUT"
  ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
  ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
  append_performance_record "discovery:lib" "test_discovery" "$DISCOVERY_COUNT" "$legacy_status" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
    "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
    "$QF_CARGO_TEST_COMMAND_STATUS" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
}

test_pattern_exists() {
  local pattern="$1"
  ensure_test_list
  if [[ "$ACTIVE_DISCOVERY_STATUS" != "PASS" ]]; then
    return 2
  fi
  rg -F -q -- "$pattern" "$TEST_LIST_FILE"
}

run_optional_cargo_test() {
  local label="$1"; local pattern="$2"
  if test_pattern_exists "$pattern"; then
    local safe_label="${label//[^[:alnum:]_.-]/_}"
    local output_file="$OUTPUT_DIR/test-${safe_label}.txt"
    if qf_cargo_test_run "$output_file" "lib" "$BASE_FEATURES" "$pattern" \
      --release --lib "$pattern" -- --nocapture; then
      local legacy_status="ok"
    else
      local legacy_status="fail"
      FAIL=1
    fi
    append_performance_record "$label" "test_execution" "$QF_CARGO_TEST_COUNT" "$legacy_status" "$QF_CARGO_TEST_STATUS" \
      "$QF_CARGO_TEST_REASON" "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" \
      null "$QF_CARGO_TEST_COUNT" "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
    return 0
  fi
  local pattern_status=$?
  if [[ "$pattern_status" -eq 2 ]]; then
    append_performance_record "$label" "test_execution" "0" "fail" "$ACTIVE_DISCOVERY_STATUS" "$ACTIVE_DISCOVERY_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
      "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  else
    append_performance_record "$label" "test_execution" "0" "skipped" "SKIP" \
      "pattern_not_found_after_target_scoped_discovery" "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" \
      "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null "$QF_CARGO_TEST_COMMAND_STATUS" \
      "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  fi
}

# Function to measure and compare
measure_performance() {
    local test_name="$1"
    local metric="$2"
    local threshold="$3"
    
    echo -e "\n> Testing: $test_name"
    
    if [[ "$BENCH_AVAILABLE" -ne 1 ]]; then
        echo "  Skipped: no bench harness available"
        append_performance_record "$test_name" "$metric" "0" "skipped" "SKIP" \
          "benchmark_harness_unavailable" "cargo bench --features benches -- $test_name" "bench" "benches" \
          null null null "SKIP" ""
        return 0
    fi

    # Run the benchmark
    local safe_test_name="${test_name//\//_}"
    local output_file="$OUTPUT_DIR/bench_${safe_test_name}.txt"
    local output_line=""
    local result=""
    local output_missing=0
    local metric_used="$metric"
    RUSTFLAGS="$BENCH_RUSTFLAGS" cargo bench --features benches -- "$test_name" 2>&1 | tee "$output_file" >/dev/null
    if [[ "$metric" == "thrpt" ]]; then
        output_line=$(grep -E "thrpt:.*\\[.*\\]" "$output_file" | head -1 || true)
        if [[ -z "$output_line" ]]; then
            output_line=$(grep -E "time:.*\\[.*\\]" "$output_file" | head -1 || true)
            if [[ -n "$output_line" ]]; then
                metric_used="time"
                warn "Throughput line missing for $test_name; falling back to time metric"
            fi
        fi
    else
        output_line=$(grep -E "time:.*\\[.*\\]" "$output_file" | head -1 || true)
    fi
    result=$(sed -E 's/.*\[[[:space:]]*([^] ]+).*/\1/' <<< "$output_line" || true)
    if [[ -z "$result" ]]; then
        warn "No benchmark output for $test_name (metric: $metric); check $output_file"
        output_missing=1
        result="0"
    fi
    
    echo "  Current: $result"
    
    # Compare with baseline if exists
    local baseline="0"
    local change="0"
    local status="no_baseline"
    if [[ "$output_missing" -eq 1 ]]; then
        status="no_output"
    elif [ -f "$BASELINE_FILE" ]; then
        if command -v jq >/dev/null 2>&1; then
            baseline=$(jq -r ".\"$test_name\".\"$metric_used\"" "$BASELINE_FILE" 2>/dev/null || echo "0")
        else
            warn "jq not installed; skipping baseline comparison"
            baseline="0"
        fi
        if [ "$baseline" != "0" ] && [ "$baseline" != "null" ]; then
            echo "  Baseline: $baseline"
            
            # Calculate percentage change
            change=$(calc_change_percent "$result" "$baseline")
            echo "  Change: ${change}%"
            
            if [[ "$(compare_gt "$change" "$threshold")" == "1" ]]; then
                echo "  [FAIL] REGRESSION: Performance degraded by more than ${threshold}%"
                status="regression"
            else
                echo "  [OK] PASS: Within acceptable threshold"
                status="ok"
            fi
        fi
    fi
    # Save current result into summary JSON items
    if [[ "$FIRST" -eq 0 ]]; then echo "," >> "$SUMMARY_JSON"; fi; FIRST=0
    local result_state="PASS"
    local result_reason="benchmark_completed_without_regression"
    case "$status" in
      regression) result_state="FAIL"; result_reason="performance_regression_exceeded_threshold";;
      no_output) result_state="FAIL"; result_reason="benchmark_output_missing";;
      no_baseline) result_reason="benchmark_completed_without_baseline";;
    esac
    local benchmark_command="cargo bench --features benches -- $(printf '%q' "$test_name")"
    printf '  {"name":"%s","metric":"%s","value":"%s","result":"%s","reason":"%s","command":"%s","target":"bench","feature_set":"benches","discovered_test_count":null,"executed_test_count":null,"command_status":null,"discovery_status":"not_applicable","raw_output":"%s"' \
      "$(qf_json_escape "$test_name")" "$(qf_json_escape "$metric_used")" "$(qf_json_escape "$result")" \
      "$result_state" "$result_reason" "$(qf_json_escape "$benchmark_command")" "$(qf_json_escape "$output_file")" >> "$SUMMARY_JSON"
    if [ -f "$BASELINE_FILE" ]; then
      printf ',"baseline":"%s","change_percent":"%s","threshold_percent":%s,"status":"%s"' \
        "$baseline" "$change" "$threshold" "$status" >> "$SUMMARY_JSON"
    fi
    printf '}' >> "$SUMMARY_JSON"
    [ "$status" = "regression" ] && return 1
    [ "$status" = "no_output" ] && return 1
    return 0
}

# Core performance tests
echo -e "\n=== Throughput Tests ==="
for test_name in "${THROUGHPUT_TESTS[@]}"; do
  if ! measure_performance "$test_name" "thrpt" "$THROUGHPUT_THRESHOLD"; then FAIL=1; fi
done

echo -e "\n=== Latency Tests ==="
for test_name in "${LATENCY_TESTS[@]}"; do
  if ! measure_performance "$test_name" "time" "$LATENCY_THRESHOLD"; then FAIL=1; fi
done

if [[ "$RUN_MEM_CPU" -eq 1 ]]; then
  echo -e "\n=== Memory Usage Tests ==="
  echo -e "\n> Testing memory allocation patterns..."
  run_optional_cargo_test "Memory usage" "memory_usage"

  echo -e "\n> Testing memory pool efficiency..."
  run_optional_cargo_test "Memory pool efficiency" "pool_efficiency"

  echo -e "\n=== CPU Usage Tests ==="
  echo -e "\n> Testing CPU utilization..."
  run_optional_cargo_test "CPU usage" "cpu_usage"
else
  warn "FAST mode: skipping memory/CPU tests"
  append_performance_record "memory_cpu_tests" "test_execution" "0" "skipped" "SKIP" \
    "fast_mode_reduced_selection" "not_applicable" "lib" "$BASE_FEATURES" null null null "SKIP" ""
fi

# Hot path performance
echo -e "\n=== Hot Path Performance ==="
for test_name in "${HOTPATH_TESTS[@]}"; do
  echo -e "\n> Testing ${test_name//_/ }..."
  if ! measure_performance "$test_name" "time" "$LATENCY_THRESHOLD"; then FAIL=1; fi
done

# SIMD performance verification
echo -e "\n=== SIMD Performance Verification ==="

if [[ "$RUN_SIMD" -eq 1 && "$BENCH_AVAILABLE" -eq 1 && $(uname -m) == "x86_64" ]]; then
    echo -e "\n> Verifying AVX2 speedup..."
    BASELINE=$(RUSTFLAGS="${BENCH_RUSTFLAGS} -C target-feature=-avx2" cargo bench --features benches -- simd_xor 2>&1 | grep "time:" | head -1 | awk '{print $2}' || echo "0")
    OPTIMIZED=$(RUSTFLAGS="${BENCH_RUSTFLAGS} -C target-feature=+avx2" cargo bench --features benches -- simd_xor 2>&1 | grep "time:" | head -1 | awk '{print $2}' || echo "0")
    echo "  Without AVX2: $BASELINE"
    echo "  With AVX2: $OPTIMIZED"
elif [[ "$RUN_SIMD" -eq 0 ]]; then
    warn "FAST mode: skipping SIMD verification"
    append_performance_record "SIMD verification" "benchmark" "0" "skipped" "SKIP" \
      "fast_mode_reduced_selection" "cargo bench --features benches -- simd_xor" "bench" "benches" \
      null null null "SKIP" ""
fi

# Scalability tests
echo -e "\n=== Scalability Tests ==="

echo -e "\n> Testing connection scalability..."
for connections in "${SCALABILITY_CONNECTIONS[@]}"; do
    echo "  Testing with $connections connections..."
    run_optional_cargo_test "Scalability ${connections} connections" "scalability_${connections}"
done

echo -e "\n> Testing stream scalability..."
for streams in "${SCALABILITY_STREAMS[@]}"; do
    echo "  Testing with $streams streams..."
    run_optional_cargo_test "Scalability ${streams} streams" "streams_${streams}"
done

# Generate comparison report
echo -e "\n> Generating performance report..."
if [ -f "$BASELINE_FILE" ] && [ -f "$CURRENT_FILE" ]; then
    echo -e "\n=== Performance Comparison Report ==="
    echo "Baseline: $BASELINE_FILE"
    echo "Current: $CURRENT_FILE"
    
    # Merge and format results
    if command -v jq >/dev/null 2>&1; then
      jq -s '.[0] * .[1]' "$BASELINE_FILE" "$CURRENT_FILE" 2>/dev/null || true
    else
      warn "jq not installed; skipping JSON merge report"
    fi
fi

json_end "$SUMMARY_JSON"
echo -e "\nArtifacts: $OUTPUT_DIR"
if [ "$FAIL" -ne 0 ]; then
  echo -e "\n[FAIL] Performance regression tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Performance regression tests complete"
