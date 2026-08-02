#!/usr/bin/env bash
# Description: Test suite runner: test-stealth-brain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; FULL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FULL=1; FAST=0;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Stealth Brain Comprehensive Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "${CARGO_FEATURES:-}" "${RUSTFLAGS_EXTRA:-}" "${JOBS:-}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Stealth + Brain Comprehensive Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

# Parameter matrix (affects StealthBrainConfig::from_env and Stealth behavior)
# Short default profile: broad enough to be informative, intentionally not exhaustive.
ACK_MAX=(6 12)
JITTER_US=(500 1500)
EXPLORE=(0.00 0.10)
PAD_MAX=(64 256)
if (( FULL )); then
  ACK_MAX=(6 8 12)
  JITTER_US=(500 1000 1500)
  EXPLORE=(0.00 0.02 0.10)
  PAD_MAX=(64 128 256)
fi
if (( FAST )); then
  ACK_MAX=(8); JITTER_US=(1000); EXPLORE=(0.02); PAD_MAX=(128)
fi

RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "stealth_brain"; FIRST=true
TOTAL=0; PASS=0; FAIL=0

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

run_one() {
  local amax="$1" jut="$2" exp="$3" pmax="$4"
  local envs=(
    "QUICFUSCATE_BRAIN_ACK_MAX=${amax}"
    "QUICFUSCATE_BRAIN_JITTER_MAX_US=${jut}"
    "QUICFUSCATE_BRAIN_EXPLORE=${exp}"
    "QUICFUSCATE_STEALTH_MODE=stealth"
    "QUICFUSCATE_PADDING_STRATEGY=2" # Adaptive
  )

  echo -e "\n> ack_max=${amax}, jitter_us=${jut}, explore=${exp}, pad_max=${pmax}" | tee -a "$LOG_FILE"
  local start=$(date +%s); ok=1
  local stealth_status=0; local brain_status=0; local probe_status=0
  local probe_result="PASS"; local probe_reason=""

  # Update padding maximum via runtime env mapped in config parsing where applicable
  # Fallback: use extra RUSTFLAGS to ensure optimized code path
  local -a run_envs=("${envs[@]}")
  if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then run_envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}"); fi
  local -a stealth_envs=("${run_envs[@]}" "QUICFUSCATE_STEALTH_MAX_PADDING=${pmax}")

  # Stealth module unit-tests (in-module)
  if run_cargo_logged "${stealth_envs[@]}" -- test --release --lib stealth:: -- --nocapture >>"$LOG_FILE" 2>&1; then
    stealth_status=0
  else
    stealth_status=$?
    ok=0
  fi

  # Brain-focused tests
  if run_cargo_logged "${run_envs[@]}" -- test --release --lib brain:: -- --nocapture >>"$LOG_FILE" 2>&1; then
    brain_status=0
  else
    brain_status=$?
    ok=0
  fi

  # Run E2E brain probe example (logs rich metrics) if available
  METR="$OUTPUT_DIR/brain_metrics.txt"
  if run_cargo_logged -- run --release --example brain_probe -- --iters 50 --jitter 5ms >>"$METR" 2>&1; then
    # Extract metrics from trace line pattern
    # Capture ack_thr, pacing, jitter_us, ivl, red_ppm
    awk '/brain: policy/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /ack_thr=/) { split($i,a,"="); sub(/\*/,"",a[2]); print "ACK_THR " a[2]; }
        if ($i ~ /pacing=/) { split($i,a,"="); sub(/\*/,"",a[2]); print "PACING " a[2]; }
        if ($i ~ /ivl=/)    { split($i,a,"="); sub(/\*/,"",a[2]); print "IVL " a[2]; }
      }
    }' "$METR" > "$OUTPUT_DIR/brain_kv.txt" || true
    # Compute summary stats for ACK_THR
    # Use local variables to avoid clobbering the outer ACK_MAX array
    local ack_stat_sum=0 ack_stat_cnt=0 ack_stat_min=999999 ack_stat_max=0
    while read -r k v; do
      if [[ "$k" == "ACK_THR" ]]; then
        n=${v%%[^0-9]*}
        [[ -z "$n" ]] && continue
        (( ack_stat_sum += n )); (( ack_stat_cnt += 1 )); (( n < ack_stat_min )) && ack_stat_min=$n; (( n > ack_stat_max )) && ack_stat_max=$n
      fi
    done < "$OUTPUT_DIR/brain_kv.txt"
    local ack_stat_avg=0
    if (( ack_stat_cnt > 0 )); then ack_stat_avg=$((ack_stat_sum/ack_stat_cnt)); fi
  else
    probe_status=$?
    probe_result="SKIP"
    probe_reason="brain_probe_unavailable_or_failed"
    echo "(brain_probe example not available or failed)" >>"$LOG_FILE"
    local ack_stat_min=0 ack_stat_max=0 ack_stat_avg=0
  fi

  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1)); if (( ok )); then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  local result="PASS"; local reason=""
  if (( ! ok )); then result="FAIL"; reason="required_cargo_test_failed"; fi

  if [[ "$FIRST" == "true" ]]; then FIRST=false; else echo "," >> "$RESULTS_JSON"; fi
  printf '  {"ack_max":%s,"jitter_us":%s,"explore":%s,"pad_max":%s,"duration_sec":%s,"ok":%s,"result":"%s","reason":"%s","command_status":{"stealth":%s,"brain":%s,"brain_probe":%s},"brain_probe_result":"%s","brain_probe_reason":"%s","ack_thr_min":%s,"ack_thr_max":%s,"ack_thr_avg":%s}' \
    "$amax" "$jut" "$exp" "$pmax" "$dur" "$ok" "$result" "$reason" "$stealth_status" "$brain_status" "$probe_status" \
    "$probe_result" "$probe_reason" "$ack_stat_min" "$ack_stat_max" "$ack_stat_avg" >> "$RESULTS_JSON"
}

for a in "${ACK_MAX[@]}"; do
  for j in "${JITTER_US[@]}"; do
    for e in "${EXPLORE[@]}"; do
      for p in "${PAD_MAX[@]}"; do
        run_one "$a" "$j" "$e" "$p"
      done
    done
  done
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  Stealth + Brain Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total runs:  $TOTAL" | tee -a "$LOG_FILE"
echo "  [OK] Passed:    $PASS" | tee -a "$LOG_FILE"
echo "  [FAIL] Failed:    $FAIL" | tee -a "$LOG_FILE"
echo "  Artifacts:   $OUTPUT_DIR" | tee -a "$LOG_FILE"

exit $(( FAIL > 0 ))
