#!/usr/bin/env bash
# Description: Deterministic FEC model-loss matrix; this is not a real QUIC/TUN gate.
# The native transport contract is owned by the tun-e2e-fec-* netns harnesses.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
CARGO_FEATURES=""
JOBS=""
SIZE=1200
K=64
BASE_SEED=424242
CARGO_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --size) SIZE="$2"; shift;;
    --k) K="$2"; shift;;
    --base-seed) BASE_SEED="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "FEC E2E Loss Suite"
      usage_common_flags 2>/dev/null || true
      cat <<USAGE
  Additional flags:
    --features LIST      Cargo feature list passed to fec_sim (default: none)
    --jobs N             Cargo build jobs passed to fec_sim (default: Cargo default)
    --size N             Payload size for fec_sim model (default: 1200)
    --k N                Number of source packets in fec_sim model (default: 64)
    --base-seed N        Base RNG seed, incremented per run (default: 424242)
USAGE
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -n "$CARGO_FEATURES" ]]; then
  CARGO_ARGS+=(--features "$CARGO_FEATURES")
fi
if [[ -n "$JOBS" ]]; then
  CARGO_ARGS+=(--jobs "$JOBS")
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  FEC E2E Loss Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Execution model: fec_sim only; no QUIC, TLS, congestion-control, ACK, or TUN path" | tee -a "$LOG_FILE"
echo "  Cargo features: ${CARGO_FEATURES:-<default>}" | tee -a "$LOG_FILE"
echo "  Cargo jobs: ${JOBS:-<default>}" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

LOSSES=(0.00 0.02 0.05 0.10 0.15 0.20)
if (( FAST )); then
  LOSSES=(0.00 0.05 0.15)
fi

RESULTS_JSON="$OUTPUT_DIR/results.json"
json_begin "$RESULTS_JSON" "tests_fec_e2e_loss"
JSON_FIRST_RUN=1

RAW_TSV="$OUTPUT_DIR/raw.tsv"
echo -e "loss\tseed\tsource_coverage_unique\tkept_systematic_unique\tdelivered_unique\trecovered\tk\tratio\tmin_ratio\tduration_ms\tok" > "$RAW_TSV"

TOTAL=0
PASS=0
FAIL=0
RUN_INDEX=0

min_ratio_for_loss() {
  local loss="$1"
  awk -v l="$loss" 'BEGIN {
    if (l <= 0.02) { printf "%.2f", 0.94; exit }
    if (l <= 0.05) { printf "%.2f", 0.88; exit }
    if (l <= 0.10) { printf "%.2f", 0.78; exit }
    if (l <= 0.15) { printf "%.2f", 0.68; exit }
    printf "%.2f", 0.58
  }'
}

for loss in "${LOSSES[@]}"; do
  seed=$((BASE_SEED + RUN_INDEX))
  RUN_INDEX=$((RUN_INDEX + 1))
  TOTAL=$((TOTAL + 1))

  run_log="$OUTPUT_DIR/loss_${loss//./_}.log"
  echo -e "\n> loss=${loss}, seed=${seed}, size=${SIZE}, k=${K}" | tee -a "$LOG_FILE"

  if run env \
    FEC_SIM_SIZE="$SIZE" \
    FEC_SIM_K="$K" \
    FEC_SIM_LOSS="$loss" \
    FEC_SIM_SEED="$seed" \
    cargo run --release --example fec_sim "${CARGO_ARGS[@]}" -- --size "$SIZE" --k "$K" --loss "$loss" \
    >"$run_log" 2>>"$LOG_FILE"; then
    :
  else
    FAIL=$((FAIL + 1))
    echo -e "${loss}\t${seed}\t0\t0\t0\t0\t${K}\t0.000000\t0.00\t0\t0" >> "$RAW_TSV"
    continue
  fi

  metric_line="$(grep '^METRIC fec_sim ' "$run_log" | tail -n1 || true)"
  if [[ -z "$metric_line" ]]; then
    FAIL=$((FAIL + 1))
    echo -e "${loss}\t${seed}\t0\t0\t0\t0\t${K}\t0.000000\t0.00\t0\t0" >> "$RAW_TSV"
    continue
  fi

  source_coverage_unique="$(echo "$metric_line" | sed -n 's/.* source_coverage_unique=\([0-9][0-9]*\).*/\1/p')"
  kept_systematic_unique="$(echo "$metric_line" | sed -n 's/.* kept_systematic_unique=\([0-9][0-9]*\).*/\1/p')"
  delivered_unique="$(echo "$metric_line" | sed -n 's/.* delivered_unique=\([0-9][0-9]*\).*/\1/p')"
  recovered="$(echo "$metric_line" | sed -n 's/.* recovered=\([0-9][0-9]*\).*/\1/p')"
  duration_ms="$(echo "$metric_line" | sed -n 's/.* duration_ms=\([0-9][0-9]*\).*/\1/p')"
  [[ -z "$source_coverage_unique" ]] && source_coverage_unique="$delivered_unique"
  [[ -z "$kept_systematic_unique" ]] && kept_systematic_unique=0
  [[ -z "$delivered_unique" ]] && delivered_unique=0
  [[ -z "$recovered" ]] && recovered=0
  [[ -z "$duration_ms" ]] && duration_ms=0

  ratio="$(awk -v d="$source_coverage_unique" -v kk="$K" 'BEGIN { if (kk <= 0) printf "0.000000"; else printf "%.6f", d / kk }')"
  min_ratio="$(min_ratio_for_loss "$loss")"
  ok="$(awk -v r="$ratio" -v m="$min_ratio" 'BEGIN { if (r + 0.0 >= m + 0.0) print 1; else print 0 }')"

  if [[ "$ok" == "1" ]]; then
    PASS=$((PASS + 1))
    info "loss=${loss} ratio=${ratio} threshold=${min_ratio} [OK]" | tee -a "$LOG_FILE"
  else
    FAIL=$((FAIL + 1))
    error "loss=${loss} ratio=${ratio} threshold=${min_ratio} [FAIL]" | tee -a "$LOG_FILE"
  fi

  echo -e "${loss}\t${seed}\t${source_coverage_unique}\t${kept_systematic_unique}\t${delivered_unique}\t${recovered}\t${K}\t${ratio}\t${min_ratio}\t${duration_ms}\t${ok}" >> "$RAW_TSV"
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  FEC E2E Loss Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total runs:  $TOTAL" | tee -a "$LOG_FILE"
echo "  [OK] Passed:    $PASS" | tee -a "$LOG_FILE"
echo "  [FAIL] Failed:    $FAIL" | tee -a "$LOG_FILE"
echo "  Artifacts:   $OUTPUT_DIR" | tee -a "$LOG_FILE"

exit $(( FAIL > 0 ))
