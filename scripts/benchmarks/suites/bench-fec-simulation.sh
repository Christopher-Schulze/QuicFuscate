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

# Try cargo bench harness; skip gracefully if not present.
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  warn "No Rust bench harness; falling back to timed test loops"
fi

MODES=(normal streaming extreme)
LOSSES=(0.0 0.05 0.20 0.40)
THREADS=(1 4 8)
if (( FAST )); then MODES=(normal streaming); LOSSES=(0.0 0.20); THREADS=(4); fi

RESULTS_JSON="$OUTPUT_DIR/bench_results.json"; json_begin "$RESULTS_JSON" "bench_fec_simulation"; JSON_FIRST_RUN=1
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
  local start=$(date +%s)
  local auto_status=0; local batch_status=0
  # Timed run of a tight subset to approximate performance
  if run_cargo_logged "${envs[@]}" -- test --release --lib \
      'fec::test_auto_mode_streaming_selection' \
      -- --nocapture >>"$LOG_FILE" 2>&1; then
    auto_status=0
  else
    auto_status=$?
  fi
  if run_cargo_logged "${envs[@]}" -- test --release --lib \
      'fec::test_batch_normal_par_counts' \
      -- --nocapture >>"$LOG_FILE" 2>&1; then
    batch_status=0
  else
    batch_status=$?
  fi
  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1))
  local result="PASS"; local reason=""
  if [[ "$auto_status" -ne 0 || "$batch_status" -ne 0 ]]; then
    result="FAIL"
    reason="one_or_more_benchmark_commands_failed"
    FAILURES=$((FAILURES+1))
  fi
  qf_json_append_object "$RESULTS_JSON" "mode=$mode" "loss=float:$loss" "threads=int:$th" \
    "duration_sec=int:$dur" "result=$result" "reason=$reason" \
    "command_status=json:{\"auto\":$auto_status,\"batch\":$batch_status}"
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
