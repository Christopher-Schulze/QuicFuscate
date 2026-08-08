#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-transport.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; DRY_RUN=0; RUSTFLAGS_EXTRA=""; JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --dry-run) DRY_RUN=1;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--fast|--full] [--dry-run] [options]"; echo "Transport Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
# shellcheck disable=SC2034
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "==============================================================="
echo "  Transport Layer Performance Benchmarks"
echo "==============================================================="
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_transport_all"; JSON_FIRST_RUN=1

if (( FAST )); then
  SELECTED_CELLS=(varint)
else
  SELECTED_CELLS=(varint packet_number)
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

append_mode_metadata

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

if (( DRY_RUN )); then
  echo "DRY-RUN: mode=$([[ "$FAST" -eq 1 ]] && echo fast || echo full) cells=${SELECTED_CELLS[*]}"
  append_skipped_cells "dry_run" 0
  json_end "$JSON"
  exit 0
fi

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
  echo "[SKIP] Cargo declares no benchmark targets; skipping transport benches."
  append_skipped_cells "no_bench_targets" 0
  json_end "$JSON"
  exit 0
fi

BENCH_JOBS=()
[[ -n "$JOBS" ]] && BENCH_JOBS+=("-j" "$JOBS")
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA}"

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

# Benchmark selected transport cells.
for cell in "${SELECTED_CELLS[@]}"; do
  case "$cell" in
    varint) echo -e "\n> Benchmarking Varint Operations...";;
    packet_number) echo -e "\n> Benchmarking Packet Number Encode...";;
  esac
  output_file="$OUTPUT_DIR/${cell//\//_}.log"
  if qf_benchmark_run "$output_file" run cargo bench "${BENCH_JOBS[@]}" --features benches -- "$cell"; then
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
    "$(qf_json_array cargo bench "${BENCH_JOBS[@]}" --features benches -- "$cell")" "$(qf_json_environment)"
done

# Export results
OUTPUT_FILE="$OUTPUT_DIR/transport-bench.json"

echo -e "\n> Exporting results to $OUTPUT_FILE..."
if qf_benchmark_run "$OUTPUT_FILE" run cargo bench "${BENCH_JOBS[@]}" --features benches --no-run --message-format=json; then
  EXPORT_STATUS=0
else
  EXPORT_STATUS="$QF_BENCH_COMMAND_STATUS"
fi
if [[ "$EXPORT_STATUS" -ne 0 ]]; then
  qf_benchmark_record "$JSON" "export" "not_measured" null "FAIL" "result_export_failed" \
    "$EXPORT_STATUS" "ci_regression" "benches" "$OUTPUT_FILE" \
    "$(qf_json_array cargo bench "${BENCH_JOBS[@]}" --features benches --no-run --message-format=json)" "$(qf_json_environment)"
  json_end "$JSON"
  exit "$EXPORT_STATUS"
fi

echo -e "\nTransport benchmark cells: ${#SELECTED_CELLS[@]}"
json_end "$JSON"
if [[ "$FAILURES" -gt 0 ]]; then
  echo "[FAIL] Transport benchmark cells failed: $FAILURES" >&2
  exit 1
fi
echo "[OK] Transport Benchmarks Complete"
