#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-fec-simulation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; RUSTFLAGS_EXTRA=""; CARGO_FEATURES=""; JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "FEC Simulation Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

export CARGO_FEATURES JOBS

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "$CARGO_FEATURES" "$RUSTFLAGS_EXTRA" "$JOBS"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Internal Machine-Room Simulation Benchmark Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

RESULTS_JSON="$OUTPUT_DIR/bench_results.json"; json_begin "$RESULTS_JSON" "bench_fec_simulation"; JSON_FIRST_RUN=1

MODES=(normal streaming extreme)
LOSSES=(0.0 0.05 0.20 0.40)
THREADS=(1 4 8)
if (( FAST )); then MODES=(normal streaming); LOSSES=(0.0 0.20); THREADS=(4); fi

# Try cargo bench harness; skip gracefully if not present.
# This suite measures with timed test loops, so an absent bench harness is genuinely
# fine. A declared harness that fails to build is not: it means the tree does not
# compile, and every timing produced afterwards would be measuring nothing meaningful.
if ! BENCH_PREFLIGHT="$(qf_bench_preflight benches)"; then
  echo "[FAIL] declared benchmark targets did not build; refusing to report timings." >&2
  for m in "${MODES[@]}"; do
    for l in "${LOSSES[@]}"; do
      for t in "${THREADS[@]}"; do
        qf_benchmark_record "$RESULTS_JSON" "fec/${m}/loss-${l}/threads-${t}" "not_measured" null \
          "FAIL" "bench_build_failed" 1 "bench" "benches" "" \
          "$(qf_json_array cargo bench --features benches -- fec_pipeline)" "$(qf_json_environment)"
      done
    done
  done
  json_end "$RESULTS_JSON"
  exit 1
fi
if [[ "$BENCH_PREFLIGHT" == "absent" ]]; then
  warn "Cargo declares no benchmark targets; using timed test loops"
fi

TOTAL=0; FAILURES=0

run_cargo_logged() {
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_cargo_logged requires -- before cargo arguments"; return 2; }
  shift
  run_cargo_with_env "${envs[@]}" -- "$@"
}

bench_one() {
  local mode="$1" loss="$2" th="$3"
  local envs=(
    "QUICFUSCATE_FEC_INITIAL_MODE=${mode}"
    "QUICFUSCATE_RS_LOSS=${loss}"
    "QUICFUSCATE_RAYON_THREADS=${th}"
  )
  if [[ -n "$RUSTFLAGS_EXTRA" ]]; then envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}"); fi
  echo -e "\n> Bench: mode=${mode}, loss=${loss}, threads=${th}" | tee -a "$LOG_FILE"
  local auto_status=0; local batch_status=0; local auto_duration=0; local batch_duration=0
  local auto_output="$OUTPUT_DIR/mode-${mode}-loss-${loss}-threads-${th}-auto.log"
  local batch_output="$OUTPUT_DIR/mode-${mode}-loss-${loss}-threads-${th}-batch.log"
  # Timed run of a tight subset to approximate performance
  if qf_benchmark_run "$auto_output" run_cargo_logged "${envs[@]}" -- test --release --lib \
      'test_auto_mode_streaming_selection' \
      -- --nocapture; then
    auto_status="$QF_BENCH_COMMAND_STATUS"
  else
    auto_status="$QF_BENCH_COMMAND_STATUS"
  fi
  auto_duration="$QF_BENCH_DURATION_SEC"
  if qf_benchmark_run "$batch_output" run_cargo_logged "${envs[@]}" -- test --release --lib \
      'test_batch_normal_par_counts' \
      -- --nocapture; then
    batch_status="$QF_BENCH_COMMAND_STATUS"
  else
    batch_status="$QF_BENCH_COMMAND_STATUS"
  fi
  batch_duration="$QF_BENCH_DURATION_SEC"
  cat "$auto_output" "$batch_output" >> "$LOG_FILE"
  local dur=$((auto_duration + batch_duration))
  TOTAL=$((TOTAL+1))
  local result="PASS"; local reason=""
  if [[ "$auto_status" -ne 0 || "$batch_status" -ne 0 ]]; then
    result="FAIL"
    reason="one_or_more_benchmark_commands_failed"
    FAILURES=$((FAILURES+1))
  else
    auto_validation_status=0
    batch_validation_status=0
    if qf_benchmark_validate_cargo_test_output "$auto_output"; then
      :
    else
      auto_validation_status="$?"
    fi
    if qf_benchmark_validate_cargo_test_output "$batch_output"; then
      :
    else
      batch_validation_status="$?"
    fi
    if [[ "$auto_validation_status" -ne 0 || "$batch_validation_status" -ne 0 ]]; then
      result="FAIL"
      reason="one_or_more_benchmark_outputs_invalid"
      FAILURES=$((FAILURES+1))
    fi
  fi
  local feature_set
  feature_set="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-}")"
  local argv_json
  argv_json="{\"auto\":$(qf_json_array cargo test --release --lib test_auto_mode_streaming_selection --features "$feature_set" -- --nocapture),\"batch\":$(qf_json_array cargo test --release --lib test_batch_normal_par_counts --features "$feature_set" -- --nocapture)}"
  local environment_json
  environment_json="$(qf_json_environment_with_assignments "${envs[@]}")"
  qf_benchmark_record "$RESULTS_JSON" \
    "fec/${mode}/loss-${loss}/threads-${th}" "duration_sec" "int:$dur" "$result" "$reason" \
    "json:{\"auto\":$auto_status,\"batch\":$batch_status}" "lib" "$feature_set" \
    "$auto_output;$batch_output" "$argv_json" "$environment_json"
}

for m in "${MODES[@]}"; do
  for l in "${LOSSES[@]}"; do
    for t in "${THREADS[@]}"; do
      bench_one "$m" "$l" "$t"
    done
  done
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Simulation Bench Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total benches: $TOTAL" | tee -a "$LOG_FILE"
echo "  Output: $OUTPUT_DIR" | tee -a "$LOG_FILE"

if [[ "$FAILURES" -gt 0 ]]; then
  echo "[FAIL] Bench suite completed with ${FAILURES} failed cells"
  exit 1
fi
echo "[OK] Bench suite complete"
