#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-stealth-brain.
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
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Stealth+Brain Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
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
echo "  Stealth + Brain Benchmark Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

ACK_MAX=(6 8 12)
JITTER_US=(500 1000 1500)
if (( FAST )); then ACK_MAX=(8); JITTER_US=(1000); fi

RESULTS_JSON="$OUTPUT_DIR/bench_results.json"; json_begin "$RESULTS_JSON" "bench_stealth_brain"; FIRST=true
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
  local amax="$1" jut="$2"
  local envs=(
    "QUICFUSCATE_BRAIN_ACK_MAX=${amax}"
    "QUICFUSCATE_BRAIN_JITTER_MAX_US=${jut}"
  )
  if [[ -n "$RUSTFLAGS_EXTRA" ]]; then envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}"); fi
  echo -e "\n> Bench: ack_max=${amax}, jitter_us=${jut}" | tee -a "$LOG_FILE"
  local start=$(date +%s)
  local stealth_status=0; local brain_status=0
  # Exercise brain + stealth module tests; measure runtime as proxy
  if run_cargo_logged "${envs[@]}" -- test --release --lib \
      'stealth::' -- --nocapture >>"$LOG_FILE" 2>&1; then
    stealth_status=0
  else
    stealth_status=$?
  fi
  if run_cargo_logged "${envs[@]}" -- test --release --lib \
      'brain::' -- --nocapture >>"$LOG_FILE" 2>&1; then
    brain_status=0
  else
    brain_status=$?
  fi
  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1))
  local result="PASS"; local reason=""
  if [[ "$stealth_status" -ne 0 || "$brain_status" -ne 0 ]]; then
    result="FAIL"
    reason="one_or_more_benchmark_commands_failed"
    FAILURES=$((FAILURES+1))
  fi
  if [[ "$FIRST" == "true" ]]; then FIRST=false; else echo "," >> "$RESULTS_JSON"; fi
  printf '  {"ack_max":%s,"jitter_us":%s,"duration_sec":%s,"result":"%s","reason":"%s","command_status":{"stealth":%s,"brain":%s}}' \
    "$amax" "$jut" "$dur" "$result" "$reason" "$stealth_status" "$brain_status" >> "$RESULTS_JSON"
}

for a in "${ACK_MAX[@]}"; do
  for j in "${JITTER_US[@]}"; do
    bench_one "$a" "$j"
  done
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  Stealth + Brain Bench Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total benches: $TOTAL" | tee -a "$LOG_FILE"
echo "  Output: $OUTPUT_DIR" | tee -a "$LOG_FILE"

if [[ "$FAILURES" -gt 0 ]]; then
  echo "[FAIL] Bench suite completed with ${FAILURES} failed cells"
  exit 1
fi
echo "[OK] Bench suite complete"
