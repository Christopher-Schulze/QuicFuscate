#!/usr/bin/env bash
# Description: Test suite runner: test-performance-regression.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FAST=0; ONLY="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --only)
      ONLY="$2"
      shift
      ;;
    --only=*)
      ONLY="${1#--only=}"
      ;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast] [--only SCOPE[,SCOPE]]"
      echo "Performance Regression Test Suite"
      echo "  --only SCOPE[,SCOPE]   Select scopes: throughput,latency,memory,cpu,hotpath,simd,scalability,report,all (default: all)"
      echo "  Scopes: throughput,latency,memory,cpu,hotpath,simd,scalability,report"
      usage_common_flags 2>/dev/null || true
      exit 0;;
    *) break;;
  esac; shift
done
PERFORMANCE_SCOPES="throughput,latency,memory,cpu,hotpath,simd,scalability,report"
if ! qf_validate_scope_selection "$ONLY" "$PERFORMANCE_SCOPES"; then
  exit 2
fi
EFFECTIVE="$ONLY"
if [[ "$ONLY" == "all" ]]; then
  EFFECTIVE="throughput,latency,memory,cpu,hotpath,simd,scalability,report"
fi
should_run_scope() {
  local scope="$1"
  qf_scope_selected "$EFFECTIVE" "$scope"
}
needs_benchmark() {
  if should_run_scope throughput || should_run_scope latency || should_run_scope hotpath; then
    return 0
  fi
  if should_run_scope simd && [[ "$(uname -m)" == "x86_64" ]]; then
    return 0
  fi
  return 1
}
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
JSON_FIRST_RUN=1
FAIL=0
# Selection record
qf_json_append_object "$SUMMARY_JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "selected_scopes=$ONLY" \
  "effective_scopes=$EFFECTIVE" \
  "mode=$( (( FAST )) && printf 'fast' || printf 'full' )" \
  "command_status=int:0" \
  "raw_output="
# Per-scope pre-execution records
for scope in throughput latency memory cpu hotpath simd scalability report; do
  # Fast profile omits memory,cpu,simd when ONLY==all
  if [[ "$ONLY" == "all" && "$FAST" -eq 1 && ( "$scope" == "memory" || "$scope" == "cpu" || "$scope" == "simd" ) ]]; then
    qf_json_append_object "$SUMMARY_JSON" \
      "name=scope:$scope" \
      "status=SKIP" \
      "result=SKIP" \
      "reason=fast_profile_omits_scope" \
      "scope=$scope" \
      "command_status=int:0" \
      "raw_output="
  elif should_run_scope "$scope"; then
    qf_json_append_object "$SUMMARY_JSON" \
      "name=scope:$scope" \
      "status=PASS" \
      "result=PASS" \
      "reason=selected" \
      "scope=$scope" \
      "command_status=int:0" \
      "raw_output="
  else
    qf_json_append_object "$SUMMARY_JSON" \
      "name=scope:$scope" \
      "status=SKIP" \
      "result=SKIP" \
      "reason=not_selected_by_scope" \
      "scope=$scope" \
      "command_status=int:0" \
      "raw_output="
  fi
done
BENCH_AVAILABLE=1
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"
BASE_FEATURES="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-}")"
DISCOVERY_DONE=0; DISCOVERY_STATUS=""; DISCOVERY_REASON=""; DISCOVERY_COUNT=0
DISCOVERY_COMMAND_STATUS=""; DISCOVERY_COMMAND=""; DISCOVERY_ARGV_JSON="[]"; DISCOVERY_TARGET=""; DISCOVERY_FEATURES=""; DISCOVERY_RAW_OUTPUT="$TEST_LIST_FILE"
ACTIVE_DISCOVERY_STATUS=""; ACTIVE_DISCOVERY_REASON=""
COMMAND_ARGV_JSON="[]"; COMMAND_ENVIRONMENT_JSON="{}"

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
  THROUGHPUT_TESTS=(aes_gcm_seal/1024B data_aead_single_seal_batch/aegis128l_1400B morus_encrypt/1024B morus_decrypt/1024B)
  LATENCY_TESTS=(connection_1rtt_send_recv/payload_1024B stream_frame_encoding/1024B_direct_writer header_validate/short_and_long)
  HOTPATH_TESTS=(varint/roundtrip_8vals packet_number/encode_all_lengths)
  RUN_MEM_CPU=1
  RUN_SIMD=1
  SCALABILITY_CONNECTIONS=(10 100 1000)
  SCALABILITY_STREAMS=(10 100 1000)
fi

BENCH_TARGET="ci_regression"

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

append_performance_record() {
  local name="$1" metric="$2" value="$3" legacy_status="$4" result="$5" reason="$6"
  local target="$8" feature_set="$9" discovered_count="${10:-null}"
  local executed_count="${11:-null}" command_status="${12:-null}"
  local discovery_status="${13:-not_applicable}" raw_output="${14:-}"
  local environment_json="${COMMAND_ENVIRONMENT_JSON:-}"
  [[ -n "$environment_json" ]] || environment_json='{}'
  qf_json_append_object "$SUMMARY_JSON" "name=$name" "metric=$metric" "value=$value" \
    "cell=$name" "status=$result" "result=$result" "reason=$reason" \
    "argv=json:${COMMAND_ARGV_JSON:-[]}" \
    "environment=json:$environment_json" \
    "target=$target" "feature_set=$feature_set" \
    "discovered_test_count=json:$discovered_count" "executed_test_count=json:$executed_count" \
    "command_status=json:$command_status" "discovery_status=$discovery_status" \
    "raw_output=$raw_output" "duration_sec=null"
}

write_current_snapshot() {
  mkdir -p "$(dirname "$CURRENT_FILE")"
  if [ -f "$SUMMARY_JSON" ]; then
    cp "$SUMMARY_JSON" "$CURRENT_FILE" 2>/dev/null || echo '{"generated":"current"}' > "$CURRENT_FILE"
  else
    echo '{"generated":"current"}' > "$CURRENT_FILE"
  fi
}

run_report_scope() {
  write_current_snapshot
  echo -e "\n> Generating performance report..."
  if [ -f "$BASELINE_FILE" ] && [ -f "$CURRENT_FILE" ]; then
    echo -e "\n=== Performance Comparison Report ==="
    echo "Baseline: $BASELINE_FILE"
    echo "Current: $CURRENT_FILE"
    if command -v jq >/dev/null 2>&1; then
      if ! jq -s '.[0] * .[1]' "$BASELINE_FILE" "$CURRENT_FILE" 2>/dev/null; then
        warn "failed to merge the benchmark comparison report"
        FAIL=1
        qf_json_append_object "$SUMMARY_JSON" "name=report" "status=FAIL" "result=FAIL" "reason=report_merge_failed" "command_status=int:1" "raw_output="
        return 1
      fi
    else
      warn "jq not installed; skipping JSON merge report"
    fi
    qf_json_append_object "$SUMMARY_JSON" "name=report" "status=PASS" "result=PASS" "reason=report_generated" "command_status=int:0" "raw_output="
  else
    warn "Baseline or current file missing; report limited"
    qf_json_append_object "$SUMMARY_JSON" "name=report" "status=SKIP" "result=SKIP" "reason=missing_baseline_or_current" "command_status=int:0" "raw_output="
  fi
}

if [[ "${QUICFUSCATE_JSON_CONTRACT_TEST:-0}" == "1" ]]; then
  COMMAND_ARGV_JSON='["json-contract-fixture"]'
  COMMAND_ENVIRONMENT_JSON='{"fixture":"non-empty"}'
  append_performance_record "json-contract-fixture" "contract" "0" "ok" "PASS" \
    "structured_environment_contract" "not_recorded" "fixture" "benches" null null null "not_applicable" ""
  json_end "$SUMMARY_JSON"
  exit 0
fi

BENCH_PREFLIGHT_STATUS=""
if needs_benchmark; then
  if BENCH_PREFLIGHT_STATUS="$(qf_bench_preflight benches "$BENCH_TARGET")" && [[ "$BENCH_PREFLIGHT_STATUS" == "present" ]]; then
    BENCH_AVAILABLE=1
  else
    if [[ "$BENCH_PREFLIGHT_STATUS" == "absent" ]]; then
      warn "Benchmark target $BENCH_TARGET is absent; requested cells will be recorded as SKIP"
    else
      warn "Benchmark target $BENCH_TARGET failed to build; requested cells will be recorded as FAIL"
      FAIL=1
    fi
    BENCH_AVAILABLE=0
  fi
else
  BENCH_AVAILABLE=0
  BENCH_PREFLIGHT_STATUS="skipped_not_required"
fi

# Build with optimizations (only when benches exist and needed)
if needs_benchmark && [[ "$BENCH_AVAILABLE" -eq 1 && "$FAST" -eq 0 ]]; then
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

ensure_test_list() {
  if [[ "$DISCOVERY_DONE" -eq 1 ]]; then
    ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
    ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_STATUS="$DISCOVERY_STATUS"; QF_CARGO_TEST_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_COUNT="$DISCOVERY_COUNT"; QF_CARGO_TEST_COMMAND_STATUS="$DISCOVERY_COMMAND_STATUS"
    QF_CARGO_TEST_COMMAND="$DISCOVERY_COMMAND"; QF_CARGO_TEST_TARGET="$DISCOVERY_TARGET"
    QF_CARGO_TEST_ARGV_JSON="$DISCOVERY_ARGV_JSON"
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
  DISCOVERY_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"
  DISCOVERY_TARGET="$QF_CARGO_TEST_TARGET"
  DISCOVERY_FEATURES="$QF_CARGO_TEST_FEATURE_SET"
  DISCOVERY_RAW_OUTPUT="$QF_CARGO_TEST_RAW_OUTPUT"
  ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
  ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
  COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
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
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
    append_performance_record "$label" "test_execution" "$QF_CARGO_TEST_COUNT" "$legacy_status" "$QF_CARGO_TEST_STATUS" \
      "$QF_CARGO_TEST_REASON" "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" \
      null "$QF_CARGO_TEST_COUNT" "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
    return 0
  fi
  local pattern_status=$?
  if [[ "$pattern_status" -eq 2 ]]; then
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
    append_performance_record "$label" "test_execution" "0" "fail" "$ACTIVE_DISCOVERY_STATUS" "$ACTIVE_DISCOVERY_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
      "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  else
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
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
        local unavailable_reason="benchmark_target_absent"
        local unavailable_result="SKIP"
        local unavailable_command_status=0
        if [[ "$BENCH_PREFLIGHT_STATUS" != "absent" ]]; then
          unavailable_reason="benchmark_target_build_failed"
          unavailable_result="FAIL"
          unavailable_command_status=1
        fi
        echo "  $unavailable_result: $unavailable_reason"
        COMMAND_ARGV_JSON="$(qf_json_array cargo bench --bench "$BENCH_TARGET" --features benches -- "$test_name")"
        COMMAND_ENVIRONMENT_JSON="$(qf_json_environment_with_assignments "RUSTFLAGS=$BENCH_RUSTFLAGS")"
        append_performance_record "$test_name" "$metric" "null" "skipped" "$unavailable_result" \
          "$unavailable_reason" "cargo bench --bench $BENCH_TARGET" "bench:$BENCH_TARGET" "benches" \
          null null "$unavailable_command_status" "$unavailable_result" ""
        return 0
    fi

    # Run the exact target and filter. Criterion exits zero for an empty
    # selection, so the output must also name the requested benchmark.
    local safe_test_name="${test_name//\//_}"
    local output_file="$OUTPUT_DIR/bench_${safe_test_name}.txt"
    local output_line=""
    local result=""
    local output_missing=0
    local metric_used="$metric"
    local failure_reason=""
    local command_status=0
    local benchmark_argv_json
    benchmark_argv_json="$(qf_json_array env "RUSTFLAGS=$BENCH_RUSTFLAGS" cargo bench --bench "$BENCH_TARGET" --features benches -- "$test_name")"
    local benchmark_environment_json
    benchmark_environment_json="$(qf_json_environment_with_assignments "RUSTFLAGS=$BENCH_RUSTFLAGS")"
    if qf_benchmark_run "$output_file" env "RUSTFLAGS=$BENCH_RUSTFLAGS" cargo bench --bench "$BENCH_TARGET" --features benches -- "$test_name"; then
        command_status=0
    else
        command_status="$QF_BENCH_COMMAND_STATUS"
    fi
    cat "$output_file"
    if [[ "$command_status" -ne 0 ]]; then
        output_missing=1
        result="null"
        failure_reason="benchmark_command_failed"
    elif ! grep -Fq "Benchmarking $test_name" "$output_file"; then
        output_missing=1
        result="null"
        failure_reason="benchmark_filter_matched_nothing"
        warn "Benchmark filter matched no declared cell: $test_name"
    fi
    if [[ "$metric" == "thrpt" ]]; then
        if [[ "$output_missing" -eq 0 ]] && grep -m1 -E "thrpt:.*\\[.*\\]" "$output_file" >"$OUTPUT_DIR/.metric-line"; then
            output_line="$(<"$OUTPUT_DIR/.metric-line")"
        elif [[ "$output_missing" -eq 0 ]] && grep -m1 -E "time:.*\\[.*\\]" "$output_file" >"$OUTPUT_DIR/.metric-line"; then
            output_line="$(<"$OUTPUT_DIR/.metric-line")"
            metric_used="time"
            warn "Throughput line missing for $test_name; recording the available time metric"
        fi
    elif [[ "$output_missing" -eq 0 ]] && grep -m1 -E "time:.*\\[.*\\]" "$output_file" >"$OUTPUT_DIR/.metric-line"; then
        output_line="$(<"$OUTPUT_DIR/.metric-line")"
    fi
    rm -f -- "$OUTPUT_DIR/.metric-line"
    if [[ "$output_missing" -eq 0 ]]; then
        result=$(sed -E 's/.*\[[[:space:]]*([^] ]+).*/\1/' <<< "$output_line")
    fi
    if [[ "$output_missing" -eq 1 ]]; then
        result="null"
    elif [[ -z "$result" || "$result" == "$output_line" ]]; then
        warn "No benchmark output for $test_name (metric: $metric); check $output_file"
        output_missing=1
        result="null"
        [[ -n "$failure_reason" ]] || failure_reason="benchmark_metric_missing"
    elif ! [[ "$result" =~ ^[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$ ]]; then
        output_missing=1
        result="null"
        failure_reason="benchmark_metric_invalid"
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
            if ! baseline=$(jq -r ".\"$test_name\".\"$metric_used\"" "$BASELINE_FILE" 2>/dev/null); then
                baseline="null"
                status="no_output"
                failure_reason="baseline_metric_invalid"
            elif ! [[ "$baseline" =~ ^[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$ ]]; then
                baseline="null"
                status="no_output"
                failure_reason="baseline_metric_invalid"
            fi
        else
            warn "jq not installed; cannot validate the baseline metric"
            baseline="null"
            status="no_output"
            failure_reason="baseline_parser_unavailable"
        fi
        if [[ "$status" != "no_output" && "$baseline" != "0" && "$baseline" != "null" ]]; then
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
    local result_state="PASS"
    local result_reason="benchmark_completed_without_regression"
    case "$status" in
      regression) result_state="FAIL"; result_reason="performance_regression_exceeded_threshold";;
      no_output) result_state="FAIL"; result_reason="${failure_reason:-benchmark_output_missing}";;
      no_baseline) result_reason="benchmark_completed_without_baseline";;
    esac
    local value_field="null"
    [[ "$result" != "null" ]] && value_field="float:$result"
    local -a benchmark_fields=(
      "name=$test_name" "cell=$test_name" "metric=$metric_used" "value=$value_field" "status=$result_state" "result=$result_state"
      "reason=$result_reason" "argv=json:$benchmark_argv_json" \
      "environment=json:$benchmark_environment_json" \
      "target=bench:$BENCH_TARGET" "feature_set=benches"
      "discovered_test_count=null" "executed_test_count=null"
      "discovery_status=not_applicable" "raw_output=$output_file" \
      "command_status=int:$command_status" "duration_sec=int:$QF_BENCH_DURATION_SEC"
    )
    if [ -f "$BASELINE_FILE" ]; then
      benchmark_fields+=("baseline=$baseline" "change_percent=$change" \
        "threshold_percent=int:$threshold" "comparison_status=$status")
    fi
    qf_json_append_object "$SUMMARY_JSON" "${benchmark_fields[@]}"
    [[ "$result_state" == "FAIL" ]] && return 1
    return 0
}

# Core performance tests
if should_run_scope throughput; then
  echo -e "\n=== Throughput Tests ==="
  for test_name in "${THROUGHPUT_TESTS[@]}"; do
    if ! measure_performance "$test_name" "thrpt" "$THROUGHPUT_THRESHOLD"; then FAIL=1; fi
  done
fi

if should_run_scope latency; then
  echo -e "\n=== Latency Tests ==="
  for test_name in "${LATENCY_TESTS[@]}"; do
    if ! measure_performance "$test_name" "time" "$LATENCY_THRESHOLD"; then FAIL=1; fi
  done
fi

if should_run_scope memory; then
  if [[ "$RUN_MEM_CPU" -eq 1 ]]; then
    echo -e "\n=== Memory Usage Tests ==="
    echo -e "\n> Testing memory allocation patterns..."
    run_optional_cargo_test "Memory usage" "memory_usage"

    echo -e "\n> Testing memory pool efficiency..."
    run_optional_cargo_test "Memory pool efficiency" "pool_efficiency"
  else
    warn "FAST mode: skipping memory tests"
    COMMAND_ARGV_JSON="[]"; COMMAND_ENVIRONMENT_JSON="{}"
    append_performance_record "memory_tests" "test_execution" "0" "skipped" "SKIP" \
      "fast_mode_reduced_selection" "not_applicable" "lib" "$BASE_FEATURES" null null null "SKIP" ""
  fi
fi

if should_run_scope cpu; then
  if [[ "$RUN_MEM_CPU" -eq 1 ]]; then
    echo -e "\n=== CPU Usage Tests ==="
    echo -e "\n> Testing CPU utilization..."
    run_optional_cargo_test "CPU usage" "cpu_usage"
  else
    warn "FAST mode: skipping CPU tests"
    COMMAND_ARGV_JSON="[]"; COMMAND_ENVIRONMENT_JSON="{}"
    append_performance_record "cpu_tests" "test_execution" "0" "skipped" "SKIP" \
      "fast_mode_reduced_selection" "not_applicable" "lib" "$BASE_FEATURES" null null null "SKIP" ""
  fi
fi

if should_run_scope hotpath; then
  # Hot path performance
  echo -e "\n=== Hot Path Performance ==="
  for test_name in "${HOTPATH_TESTS[@]}"; do
    echo -e "\n> Testing ${test_name//_/ }..."
    if ! measure_performance "$test_name" "time" "$LATENCY_THRESHOLD"; then FAIL=1; fi
  done
fi
if should_run_scope simd; then
  echo -e "\n=== SIMD Performance Verification ==="
  if [[ "$RUN_SIMD" -eq 1 && "$BENCH_AVAILABLE" -eq 1 && $(uname -m) == "x86_64" ]]; then
    echo -e "\n> Verifying AVX2 comparison on sort_simd/1024_elems..."
    for simd_mode in without_avx2 with_avx2; do
      if [[ "$simd_mode" == "without_avx2" ]]; then
        simd_flags="${BENCH_RUSTFLAGS} -C target-feature=-avx2"
      else
        simd_flags="${BENCH_RUSTFLAGS} -C target-feature=+avx2"
      fi
      simd_output="$OUTPUT_DIR/bench-simd-${simd_mode}.txt"
      simd_status=0
      if qf_benchmark_run "$simd_output" env "RUSTFLAGS=$simd_flags" cargo bench --bench "$BENCH_TARGET" --features benches -- sort_simd/1024_elems; then
        simd_status=0
      else
        simd_status="$QF_BENCH_COMMAND_STATUS"
      fi
      cat "$simd_output"
      simd_result="null"
      simd_state="PASS"
      simd_reason=""
      if [[ "$simd_status" -ne 0 ]]; then
        simd_state="FAIL"
        simd_reason="benchmark_command_failed"
      elif ! grep -Fq "Benchmarking sort_simd/1024_elems" "$simd_output"; then
        simd_state="FAIL"
        simd_reason="benchmark_filter_matched_nothing"
      elif ! grep -m1 -E "time:.*\[.*\]" "$simd_output" >"$OUTPUT_DIR/.simd-line"; then
        simd_state="FAIL"
        simd_reason="benchmark_metric_missing"
      else
        simd_result="$(sed -E 's/.*\[[[:space:]]*([^] ]+).*/\1/' "$OUTPUT_DIR/.simd-line")"
        if ! [[ "$simd_result" =~ ^[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$ ]]; then
          simd_state="FAIL"
          simd_reason="benchmark_metric_invalid"
          simd_result="null"
        fi
      fi
      rm -f -- "$OUTPUT_DIR/.simd-line"
      [[ "$simd_state" == "FAIL" ]] && FAIL=1
      simd_value="null"
      [[ "$simd_result" != "null" ]] && simd_value="float:$simd_result"
      qf_benchmark_record "$SUMMARY_JSON" "simd/${simd_mode}" "time" "$simd_value" \
        "$simd_state" "$simd_reason" "$simd_status" "bench:$BENCH_TARGET" "benches" "$simd_output" \
        "$(qf_json_array env "RUSTFLAGS=$simd_flags" cargo bench --bench "$BENCH_TARGET" --features benches -- sort_simd/1024_elems)" \
        "$(qf_json_environment_with_assignments "RUSTFLAGS=$simd_flags")"
    done
  elif [[ "$RUN_SIMD" -eq 0 ]]; then
    warn "FAST mode: skipping SIMD verification"
    qf_benchmark_record "$SUMMARY_JSON" "simd/verification" "not_measured" null "SKIP" \
      "fast_mode_reduced_selection" 0 "bench:$BENCH_TARGET" "benches" "" \
      "$(qf_json_array cargo bench --bench "$BENCH_TARGET" --features benches -- sort_simd/1024_elems)" "$(qf_json_environment)"
  else
    qf_benchmark_record "$SUMMARY_JSON" "simd/verification" "not_measured" null "SKIP" \
      "platform_requires_x86_64" 0 "bench:$BENCH_TARGET" "benches" "" \
      "$(qf_json_array cargo bench --bench "$BENCH_TARGET" --features benches -- sort_simd/1024_elems)" "$(qf_json_environment)"
  fi
fi

if should_run_scope scalability; then
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
fi

if should_run_scope report; then
  run_report_scope
fi

json_end "$SUMMARY_JSON"
echo -e "\nArtifacts: $OUTPUT_DIR"
if [ "$FAIL" -ne 0 ]; then
  echo -e "\n[FAIL] Performance regression tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Performance regression tests complete"
