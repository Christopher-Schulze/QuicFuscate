#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-optimization.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FAST=0; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --dry-run) DRY_RUN=1;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast|--full] [--dry-run]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_optimization_all"; JSON_FIRST_RUN=1

if (( FAST )); then
  SELECTED_CELLS=(sort_simd/1024_elems)
else
  SELECTED_CELLS=(sort_simd shuffle_simd)
fi
FAILURES=0

append_mode_metadata() {
  local mode="full"
  (( FAST )) && mode="fast"
  local cells_json="["
  local cell
  for cell in "${SELECTED_CELLS[@]}"; do
    [[ "$cells_json" == "[" ]] || cells_json+=","
    cells_json+="\"$(qf_json_escape "$cell")\""
  done
  cells_json+="]"
  qf_json_append_object "$JSON" "cell=meta" "result=PASS" "reason=" "argv=json:[]" "environment=json:$(qf_json_environment)" \
    "command_status=int:0" \
    "meta=json:{\"mode\":\"$mode\",\"fast\":$FAST,\"selected_cells\":$cells_json,\"cell_count\":${#SELECTED_CELLS[@]}}"
}

append_skipped_cells() {
  local reason="$1"
  local command_status="${2:-0}"
  local cell
  for cell in "${SELECTED_CELLS[@]}"; do
    qf_benchmark_record "$JSON" "$cell" "not_measured" null "SKIP" "$reason" \
      "$command_status" "ci_regression" "benches" "" \
      "$(qf_json_array cargo bench --features benches -- "$cell")" "$(qf_json_environment)"
  done
}

append_mode_metadata
if (( DRY_RUN )); then
  echo "DRY-RUN: mode=$([[ "$FAST" -eq 1 ]] && echo fast || echo full) cells=${SELECTED_CELLS[*]}"
  append_skipped_cells "dry_run" 0
  json_end "$JSON"
  exit 0
fi

echo "==============================================================="
echo "  Optimization & Hardware Acceleration Benchmarks"
echo "==============================================================="

# Skip gracefully if bench harness absent
# Absence and build failure are different answers. A nonzero --no-run used to report
# both as "no benches detected", so a compile error produced a green skip and could be
# read as a completed performance check.
BENCH_PREFLIGHT="$(qf_bench_preflight benches)" || {
  echo "[FAIL] declared benchmark targets did not build; refusing to report a skip." >&2
  for cell in "${SELECTED_CELLS[@]}"; do
    qf_benchmark_record "$JSON" "$cell" "not_measured" null "FAIL" "bench_build_failed" \
      1 "ci_regression" "benches" "" \
      "$(qf_json_array cargo bench --features benches -- "$cell")" "$(qf_json_environment)"
  done
  json_end "$JSON"
  exit 1
}
if [[ "$BENCH_PREFLIGHT" == "absent" ]]; then
  echo "[SKIP] Cargo declares no benchmark targets; skipping optimization benches."
  append_skipped_cells "no_bench_targets" 0
  json_end "$JSON"
  exit 0
fi

BUILD_OUTPUT="$OUTPUT_DIR/build.log"
if qf_benchmark_run "$BUILD_OUTPUT" run_cargo build --release --features "${CARGO_FEATURES:-benches}"; then
  BUILD_STATUS=0
else
  BUILD_STATUS="$QF_BENCH_COMMAND_STATUS"
fi
cat "$BUILD_OUTPUT"
if [[ "$BUILD_STATUS" -ne 0 ]]; then
  for cell in "${SELECTED_CELLS[@]}"; do
    qf_benchmark_record "$JSON" "$cell" "not_measured" null "FAIL" "harness_build_failed" \
      "$BUILD_STATUS" "ci_regression" "${CARGO_FEATURES:-benches}" "$BUILD_OUTPUT" \
      "$(qf_json_array cargo build --release --features "${CARGO_FEATURES:-benches}")" "$(qf_json_environment)"
  done
  json_end "$JSON"
  exit "$BUILD_STATUS"
fi

for cell in "${SELECTED_CELLS[@]}"; do
  case "$cell" in
    sort_simd) echo -e "\n> Benchmarking SIMD Sort (u32)...";;
    sort_simd/1024_elems) echo -e "\n> Benchmarking SIMD Sort (u32, fast cell)...";;
    shuffle_simd) echo -e "\n> Benchmarking SIMD Shuffle...";;
  esac
  output_file="$OUTPUT_DIR/${cell//\//_}.log"
  if qf_benchmark_run "$output_file" run cargo bench --features benches -- "$cell"; then
    result="PASS"; reason=""; command_status=0
  else
    result="FAIL"; reason="benchmark_command_failed"; command_status="$QF_BENCH_COMMAND_STATUS"
  fi
  if [[ "$result" == "PASS" ]]; then
    validation_status=0
    if qf_benchmark_validate_criterion_output "$output_file" "$cell"; then
      :
    else
      validation_status="$?"
      result="FAIL"
      case "$validation_status" in
        2) reason="benchmark_output_missing";;
        3) reason="benchmark_filter_matched_nothing";;
        4) reason="benchmark_metric_missing";;
        *) reason="benchmark_metric_invalid";;
      esac
    fi
  fi
  [[ "$result" == "FAIL" ]] && FAILURES=$((FAILURES + 1))
  cat "$output_file"
  qf_benchmark_record "$JSON" "$cell" "duration_sec" "int:$QF_BENCH_DURATION_SEC" \
    "$result" "$reason" "$command_status" "ci_regression" "benches" "$output_file" \
    "$(qf_json_array cargo bench --features benches -- "$cell")" "$(qf_json_environment)"
done

echo -e "\nOptimization benchmark cells: ${#SELECTED_CELLS[@]}"
json_end "$JSON"
if [[ "$FAILURES" -gt 0 ]]; then
  echo "[FAIL] Optimization benchmark cells failed: $FAILURES" >&2
  exit 1
fi
echo "[OK] Optimization Benchmarks Complete"
