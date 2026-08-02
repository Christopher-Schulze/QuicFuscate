#!/usr/bin/env bash
# Description: Test suite runner: test-optimization.
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
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
validate_feature_list "CARGO_FEATURES" "${CARGO_FEATURES:-}"
validate_control_free_value "RUSTFLAGS_EXTRA" "${RUSTFLAGS_EXTRA:-}" 8192
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "tests_optimization"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Optimization & Hardware Acceleration Test Suite"
echo "==============================================================="

TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"
BASE_FEATURES="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-}")"
BASE_DISCOVERY_DONE=0; BASE_DISCOVERY_STATUS=""; BASE_DISCOVERY_REASON=""
BASE_DISCOVERY_COUNT=0; BASE_DISCOVERY_COMMAND_STATUS=""; BASE_DISCOVERY_COMMAND=""; BASE_DISCOVERY_TARGET=""; BASE_DISCOVERY_FEATURES=""; BASE_DISCOVERY_RAW_OUTPUT="$TEST_LIST_FILE"
ZERO_COPY_DISCOVERY_DONE=0; ZERO_COPY_DISCOVERY_STATUS=""; ZERO_COPY_DISCOVERY_REASON=""
ZERO_COPY_DISCOVERY_COUNT=0; ZERO_COPY_DISCOVERY_COMMAND_STATUS=""; ZERO_COPY_DISCOVERY_COMMAND=""; ZERO_COPY_DISCOVERY_TARGET=""; ZERO_COPY_DISCOVERY_FEATURES=""; ZERO_COPY_DISCOVERY_RAW_OUTPUT=""
ACTIVE_TEST_LIST_FILE="$TEST_LIST_FILE"; ACTIVE_DISCOVERY_STATUS=""; ACTIVE_DISCOVERY_REASON=""
DISCOVERY_STATUS_FOR_RUN="not_applicable"

append_json_record() {
  local name="$1" legacy_status="$2" dur="$3" result="$4" reason="$5"
  local command="$6" target="$7" feature_set="$8" discovered_count="${9:-null}"
  local executed_count="${10:-null}" command_status="${11:-null}"
  local discovery_status="${12:-not_applicable}" raw_output="${13:-}"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  printf '  {"name":"%s","status":"%s","result":"%s","reason":"%s","command":"%s","target":"%s","feature_set":"%s","discovered_test_count":%s,"executed_test_count":%s,"command_status":%s,"discovery_status":"%s","raw_output":"%s","duration_sec":%s}' \
    "$(qf_json_escape "$name")" "$(qf_json_escape "$legacy_status")" "$(qf_json_escape "$result")" \
    "$(qf_json_escape "$reason")" "$(qf_json_escape "$command")" "$(qf_json_escape "$target")" \
    "$(qf_json_escape "$feature_set")" "$discovered_count" "$executed_count" "$command_status" \
    "$(qf_json_escape "$discovery_status")" "$(qf_json_escape "$raw_output")" "$dur" >> "$RESULTS_JSON"
}

append_json() {
  local name="$1" status="$2" dur="$3"
  local result="PASS"
  case "$status" in
    fail) result="FAIL";;
    skipped) result="SKIP";;
  esac
  append_json_record "$name" "$status" "$dur" "$result" "legacy_case_without_structured_cargo_metadata" \
    "not_recorded" "not_recorded" "not_recorded" null null null "not_applicable" ""
}

record_platform_skip() {
  local name="$1" reason="$2" target="${3:-not_applicable}" feature_set="${4:-$BASE_FEATURES}"
  SKIPPED=$((SKIPPED+1))
  append_json_record "$name" "skipped" 0 "SKIP" "$reason" "not_applicable" "$target" "$feature_set" \
    null null null "SKIP" ""
}

ensure_test_list() {
  local feature_set="${1:-$BASE_FEATURES}"
  local scope="base"
  local list_file="$TEST_LIST_FILE"
  if [[ "$feature_set" != "$BASE_FEATURES" ]]; then
    scope="zero-copy"
    list_file="$OUTPUT_DIR/testlist-zero-copy.txt"
  fi

  if [[ "$scope" == "base" && "$BASE_DISCOVERY_DONE" -eq 1 ]] || \
     [[ "$scope" == "zero-copy" && "$ZERO_COPY_DISCOVERY_DONE" -eq 1 ]]; then
    ACTIVE_TEST_LIST_FILE="$list_file"
    if [[ "$scope" == "base" ]]; then
      ACTIVE_DISCOVERY_STATUS="$BASE_DISCOVERY_STATUS"
      ACTIVE_DISCOVERY_REASON="$BASE_DISCOVERY_REASON"
      QF_CARGO_TEST_STATUS="$BASE_DISCOVERY_STATUS"; QF_CARGO_TEST_REASON="$BASE_DISCOVERY_REASON"
      QF_CARGO_TEST_COUNT="$BASE_DISCOVERY_COUNT"; QF_CARGO_TEST_COMMAND_STATUS="$BASE_DISCOVERY_COMMAND_STATUS"
      QF_CARGO_TEST_COMMAND="$BASE_DISCOVERY_COMMAND"; QF_CARGO_TEST_TARGET="$BASE_DISCOVERY_TARGET"
      QF_CARGO_TEST_FEATURE_SET="$BASE_DISCOVERY_FEATURES"; QF_CARGO_TEST_FILTER="<all>"
      QF_CARGO_TEST_RAW_OUTPUT="$BASE_DISCOVERY_RAW_OUTPUT"
    else
      ACTIVE_DISCOVERY_STATUS="$ZERO_COPY_DISCOVERY_STATUS"
      ACTIVE_DISCOVERY_REASON="$ZERO_COPY_DISCOVERY_REASON"
      QF_CARGO_TEST_STATUS="$ZERO_COPY_DISCOVERY_STATUS"; QF_CARGO_TEST_REASON="$ZERO_COPY_DISCOVERY_REASON"
      QF_CARGO_TEST_COUNT="$ZERO_COPY_DISCOVERY_COUNT"; QF_CARGO_TEST_COMMAND_STATUS="$ZERO_COPY_DISCOVERY_COMMAND_STATUS"
      QF_CARGO_TEST_COMMAND="$ZERO_COPY_DISCOVERY_COMMAND"; QF_CARGO_TEST_TARGET="$ZERO_COPY_DISCOVERY_TARGET"
      QF_CARGO_TEST_FEATURE_SET="$ZERO_COPY_DISCOVERY_FEATURES"; QF_CARGO_TEST_FILTER="<all>"
      QF_CARGO_TEST_RAW_OUTPUT="$ZERO_COPY_DISCOVERY_RAW_OUTPUT"
    fi
    return 0
  fi

  if qf_cargo_test_discover "$list_file" "lib" "$feature_set" --release --lib; then
    local legacy_status="ok"
  else
    local legacy_status="fail"
    FAILED=$((FAILED+1))
  fi
  if [[ "$scope" == "base" ]]; then
    BASE_DISCOVERY_DONE=1
    BASE_DISCOVERY_STATUS="$QF_CARGO_TEST_STATUS"
    BASE_DISCOVERY_REASON="$QF_CARGO_TEST_REASON"
    BASE_DISCOVERY_COUNT="$QF_CARGO_TEST_COUNT"
    BASE_DISCOVERY_COMMAND_STATUS="$QF_CARGO_TEST_COMMAND_STATUS"
    BASE_DISCOVERY_COMMAND="$QF_CARGO_TEST_COMMAND"
    BASE_DISCOVERY_TARGET="$QF_CARGO_TEST_TARGET"
    BASE_DISCOVERY_FEATURES="$QF_CARGO_TEST_FEATURE_SET"
    BASE_DISCOVERY_RAW_OUTPUT="$QF_CARGO_TEST_RAW_OUTPUT"
  else
    ZERO_COPY_DISCOVERY_DONE=1
    ZERO_COPY_DISCOVERY_STATUS="$QF_CARGO_TEST_STATUS"
    ZERO_COPY_DISCOVERY_REASON="$QF_CARGO_TEST_REASON"
    ZERO_COPY_DISCOVERY_COUNT="$QF_CARGO_TEST_COUNT"
    ZERO_COPY_DISCOVERY_COMMAND_STATUS="$QF_CARGO_TEST_COMMAND_STATUS"
    ZERO_COPY_DISCOVERY_COMMAND="$QF_CARGO_TEST_COMMAND"
    ZERO_COPY_DISCOVERY_TARGET="$QF_CARGO_TEST_TARGET"
    ZERO_COPY_DISCOVERY_FEATURES="$QF_CARGO_TEST_FEATURE_SET"
    ZERO_COPY_DISCOVERY_RAW_OUTPUT="$QF_CARGO_TEST_RAW_OUTPUT"
  fi
  ACTIVE_TEST_LIST_FILE="$list_file"
  ACTIVE_DISCOVERY_STATUS="$QF_CARGO_TEST_STATUS"
  ACTIVE_DISCOVERY_REASON="$QF_CARGO_TEST_REASON"
  append_json_record "discovery:${scope}" "$legacy_status" 0 "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
    "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" \
    "$QF_CARGO_TEST_COUNT" null "$QF_CARGO_TEST_COMMAND_STATUS" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
}

test_pattern_exists() {
  local pattern="$1"
  local feature_set="${2:-$BASE_FEATURES}"
  if (( FAST )); then
    # Fast mode uses a curated direct invocation and intentionally has no list discovery.
    ACTIVE_DISCOVERY_STATUS="SKIP"
    ACTIVE_DISCOVERY_REASON="fast_mode_curated_direct_selection"
    return 0
  fi
  ensure_test_list "$feature_set"
  if [[ "$ACTIVE_DISCOVERY_STATUS" != "PASS" ]]; then
    return 2
  fi
  rg -F -q -- "$pattern" "$ACTIVE_TEST_LIST_FILE"
}

run_optional_test() {
  local label="$1"; local pattern="$2"; local feature_set="${3:-$BASE_FEATURES}"
  local feature_arg="${4:-}"
  shift 4
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_optional_test requires -- before runner arguments"; return 2; }
  shift
  local -a runner_args=(--nocapture)
  if [[ "$#" -gt 0 ]]; then runner_args=("$@"); fi
  if test_pattern_exists "$pattern" "$feature_set"; then
    DISCOVERY_STATUS_FOR_RUN="$ACTIVE_DISCOVERY_STATUS"
    local -a command=(cargo test --release --lib "$pattern" -- "${runner_args[@]}")
    if [[ -n "$feature_arg" ]]; then
      command=(cargo test --release --features "$feature_arg" --lib "$pattern" -- "${runner_args[@]}")
    fi
    run_case "$label" "${envs[@]}" -- "${command[@]}"
    DISCOVERY_STATUS_FOR_RUN="not_applicable"
    return 0
  fi
  local pattern_status=$?
  if [[ "$pattern_status" -eq 2 ]]; then
    append_json_record "$label" "fail" 0 "$ACTIVE_DISCOVERY_STATUS" "$ACTIVE_DISCOVERY_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" \
      "$QF_CARGO_TEST_COUNT" null "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  else
    SKIPPED=$((SKIPPED+1))
    append_json_record "$label" "skipped" 0 "SKIP" "pattern_not_found_after_target_scoped_discovery" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" \
      "$QF_CARGO_TEST_COUNT" null "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  fi
  return 0
}

run_cargo_test_capture() {
  local output_file="$1"
  shift
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_cargo_test_capture requires -- before command"; return 2; }
  shift
  local -a cmd=("$@")
  local command_status=0
  if ( LOG_FILE="" JSON="" JSON_FILE="" run_cargo_with_env "${envs[@]}" -- "${cmd[@]:1}" ) > "$output_file" 2>&1; then
    command_status=0
  else
    command_status=$?
  fi
  return "$command_status"
}

run_case() {
  local name="$1"; shift
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_case requires -- before command"; return 2; }
  shift
  local cmd=("$@")
  local start=$(date +%s)
  TOTAL=$((TOTAL+1))
  echo -e "\n> [$TOTAL] $name"
  [[ ${#envs[@]} -gt 0 ]] && echo "  Env: ${envs[*]}"
  echo "  Cmd: ${cmd[*]}"
  if [[ "${cmd[0]:-}" == "cargo" && "${cmd[1]:-}" == "test" ]]; then
    local output_file="$OUTPUT_DIR/cargo-test-${TOTAL}.txt"
    local command_status=0
    if run_cargo_test_capture "$output_file" "${envs[@]}" -- "${cmd[@]}"; then
      command_status=0
    else
      command_status=$?
    fi
    cat "$output_file"
    qf_cargo_test_metadata_from_args "${cmd[@]:1}"
    if qf_cargo_test_classify_output run "$output_file" "$command_status" \
      "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_FILTER" "$QF_CARGO_TEST_COMMAND"; then
      :
    else
      :
    fi
    local duration=$(( $(date +%s) - start ))
    local legacy_status="ok"
    if [[ "$QF_CARGO_TEST_STATUS" != "PASS" ]]; then legacy_status="fail"; fi
    if [[ "$QF_CARGO_TEST_STATUS" == "PASS" ]]; then PASSED=$((PASSED+1)); else FAILED=$((FAILED+1)); fi
    append_json_record "$name" "$legacy_status" "$duration" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" null \
      "$QF_CARGO_TEST_COUNT" "$QF_CARGO_TEST_COMMAND_STATUS" "$DISCOVERY_STATUS_FOR_RUN" "$QF_CARGO_TEST_RAW_OUTPUT"
    DISCOVERY_STATUS_FOR_RUN="not_applicable"
    return 0
  fi
  if [[ ${#envs[@]} -gt 0 ]]; then
    if run env "${envs[@]}" "${cmd[@]}"; then
      PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
    fi
  elif run "${cmd[@]}"; then
    PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
  fi
  FAILED=$((FAILED+1))
  append_json "$name" "fail" $(( $(date +%s) - start ))
  return 0
}

run_named_test() {
  local label="$1"; shift
  local pattern="$1"; shift
  run_optional_test "$label" "$pattern" "$BASE_FEATURES" "" --
}

# Test I/O batch sizing
echo -e "\n> Testing I/O Batch Sizing..."
run_named_test "I/O batch sizing" "normalized_batch_size"

if (( FAST )); then
  echo -e "\n> Fast mode enabled (reduced optimization matrix)"
  run_named_test "CPU profile telemetry mask" "cpu_profile_mask"
  run_named_test "FEC batch processing" "test_batch_"
  run_optional_test "Telemetry system" "telemetry" "$BASE_FEATURES" "" "QUICFUSCATE_TELEMETRY=1" --

  FEATURES="${CARGO_FEATURES:-rust-tests}"
  if [[ ",${FEATURES}," != *",rust-tests,"* ]]; then
    FEATURES="${FEATURES},rust-tests"
  fi
  if [[ ",${FEATURES}," != *",simd-selfcheck,"* ]]; then
    FEATURES="${FEATURES},simd-selfcheck"
  fi
  SIMD_FAST_TEST_ARGS=(
    --test rt-argsort-parity
    --test rt-bitmap-range-parity
    --test rt-brain-activation-parity
    --test rt-iter-reductions
    --test rt-simd-selfcheck
    --test rt-telemetry-counters
    --test rt-xor-repeating-parity
  )
  if [[ "$(uname -m)" == "x86_64" ]]; then
    SIMD_FAST_TEST_ARGS+=(--test rt-ack-merge-parity --test rt-xor-sse2-parity)
  fi
  run_case "SIMD/Accelerate integration" -- cargo test --release --features "$FEATURES" \
    "${SIMD_FAST_TEST_ARGS[@]}" \
    -- --nocapture

  echo -e "\n==============================================================="
  echo "  Optimization Test Summary"
  echo "==============================================================="
  echo "  Total:   $TOTAL"
  echo "  Passed:  $PASSED"
  echo "  Failed:  $FAILED"
  echo "  Skipped: $SKIPPED"
  json_end "$RESULTS_JSON"
  if [[ "$FAILED" -gt 0 ]]; then
    echo -e "\n[FAIL] Optimization Tests completed with failures"
    exit 1
  fi
  echo -e "\n[OK] Optimization Fast Tests Complete"
  exit 0
fi

# Test NUMA awareness
echo -e "\n> Testing NUMA Awareness..."
run_optional_test "NUMA local" "numa" "$BASE_FEATURES" "" "QUICFUSCATE_NUMA_POLICY=local" --
run_optional_test "NUMA interleave" "numa" "$BASE_FEATURES" "" "QUICFUSCATE_NUMA_POLICY=interleave" --
run_optional_test "NUMA preferred" "numa" "$BASE_FEATURES" "" "QUICFUSCATE_NUMA_POLICY=preferred:0" --

# Test HugePages
echo -e "\n> Testing HugePages Support..."
run_optional_test "HugePages" "hugepages" "$BASE_FEATURES" "" "QUICFUSCATE_MADVISE_HUGEPAGE=1" --

# Test SIMD paths (x86_64)
echo -e "\n> Testing x86_64 SIMD Paths..."
if [[ $(uname -m) == "x86_64" ]]; then
    echo "  - Testing SSE2..."
    run_optional_test "SSE2 paths" "sse2" "$BASE_FEATURES" "" "RUSTFLAGS=-Ctarget-feature=+sse2" --
    
    echo "  - Testing AVX2..."
    run_optional_test "AVX2 paths" "avx2" "$BASE_FEATURES" "" "RUSTFLAGS=-Ctarget-feature=+avx2" --
    
    echo "  - Testing AVX-512..."
    run_optional_test "AVX-512 paths" "avx512" "$BASE_FEATURES" "" "RUSTFLAGS=-Ctarget-feature=+avx512f" --
else
    echo "  Skipping (x86_64 only)"
    record_platform_skip "x86_64 SIMD paths" "host_arch_not_x86_64" "x86_64" "$BASE_FEATURES"
fi

# Test SIMD paths (ARM)
echo -e "\n> Testing ARM SIMD Paths..."
if [[ $(uname -m) == "aarch64" ]] || [[ $(uname -m) == "arm64" ]]; then
    echo "  - Testing NEON..."
    run_optional_test "NEON paths" "neon" "$BASE_FEATURES" "" --
    
    echo "  - Testing PMULL..."
    run_optional_test "PMULL paths" "pmull" "$BASE_FEATURES" "" --
else
    echo "  Skipping (ARM only)"
    record_platform_skip "ARM SIMD paths" "host_arch_not_arm64" "arm64" "$BASE_FEATURES"
fi

# Test CPU feature detection
echo -e "\n> Testing CPU Feature Detection..."
run_named_test "CPU feature detection" "cpu_features"

# Test prefetching
echo -e "\n> Testing Prefetch Hints..."
run_named_test "Prefetch hints" "prefetch"

# Test cache alignment
echo -e "\n> Testing Cache Line Alignment..."
run_named_test "Cache alignment" "cache_alignment"

# Test zero-copy operations
echo -e "\n> Testing Zero-Copy Operations..."
ZERO_COPY_FEATURES="$(qf_cargo_test_feature_set "${BASE_FEATURES},zero_copy_dgram")"
run_optional_test "Zero-copy operations" "zero_copy" "$ZERO_COPY_FEATURES" "zero_copy_dgram" --

# Test batch processing
echo -e "\n> Testing Batch Processing..."
run_named_test "Batch processing" "batch_processing"

# Test telemetry
echo -e "\n> Testing Telemetry System..."
run_optional_test "Telemetry system" "telemetry" "$BASE_FEATURES" "" "QUICFUSCATE_TELEMETRY=1" --

# Integration fixtures (SIMD/accelerate/telemetry)
FEATURES="${CARGO_FEATURES:-rust-tests}"
if [[ ",${FEATURES}," != *",rust-tests,"* ]]; then
  FEATURES="${FEATURES},rust-tests"
fi
if [[ ",${FEATURES}," != *",simd-selfcheck,"* ]]; then
  FEATURES="${FEATURES},simd-selfcheck"
fi
echo -e "\n> Running SIMD/Accelerate Integration Fixtures..."
SIMD_FULL_TEST_ARGS=(
  --test rt-argsort-parity
  --test rt-base64-decode-parity
  --test rt-bitmap-range-parity
  --test rt-bitstream-parity
  --test rt-brain-activation-parity
  --test rt-brain-histogram
  --test rt-ecn-popcount
  --test rt-header-validate-parity
  --test rt-iter-reduction-telemetry
  --test rt-iter-reductions
  --test rt-moving-average-parity
  --test rt-packet-number-parity
  --test rt-random-aes-ctr
  --test rt-ring-buffer-parity
  --test rt-shuffle-parity
  --test rt-simd-selfcheck
  --test rt-telemetry-counters
  --test rt-transpose-parity
  --test rt-varint-roundtrip
  --test rt-xor-parity
  --test rt-xor-repeating-parity
)
if [[ "$(uname -m)" == "x86_64" ]]; then
  SIMD_FULL_TEST_ARGS+=(--test rt-ack-merge-parity --test rt-xor-sse2-parity)
fi
run_case "SIMD/Accelerate integration" -- cargo test --release --features "$FEATURES" \
  "${SIMD_FULL_TEST_ARGS[@]}" \
  -- --nocapture

# Combined optimization test
echo -e "\n> Running Optimization Stress Test..."
run_optional_test "Optimization stress" "optimization_stress" "$BASE_FEATURES" "" \
  "QUICFUSCATE_NUMA_POLICY=interleave" \
  "QUICFUSCATE_MADVISE_HUGEPAGE=1" \
  "QUICFUSCATE_TELEMETRY=1" \
  "RUSTFLAGS=-Ctarget-cpu=native" -- \
  --nocapture --test-threads=1

echo -e "\n==============================================================="
echo "  Optimization Test Summary"
echo "==============================================================="
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
json_end "$RESULTS_JSON"
if [[ "$FAILED" -gt 0 ]]; then
  echo -e "\n[FAIL] Optimization Tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Optimization Tests Complete"
