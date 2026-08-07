#!/usr/bin/env bash
# Description: Test suite runner: test-fec-simulation.
#
# Proof boundary: every matrix cell runs the same focused test,
# fec::test_auto_mode_streaming_selection, under a different runtime environment
# (mode, loss, threads, GF16 toggle, stream cadence, adaptive RS). The matrix therefore
# proves that the selection test stays green across those configurations. It does NOT
# prove that each dimension drives a different code path; per-dimension path divergence
# is owned by the focused unit tests in src/fec, not by this suite. Read a green matrix
# as configuration robustness, not as per-dimension coverage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; COMPACT=1; RUSTFLAGS_EXTRA=""; CARGO_FEATURES=""; JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1; COMPACT=1;;
    --compact) COMPACT=1;;
    --full) COMPACT=0; FAST=0;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "FEC Simulation Comprehensive Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "$CARGO_FEATURES" "$RUSTFLAGS_EXTRA" "$JOBS"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Internal Machine-Room Simulation Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

# Parameter matrix (tunable)
MODES=(zero light normal medium strong extreme streaming)
LOSSES=(0.0 0.005 0.01 0.02 0.05 0.10 0.15 0.20 0.30 0.40 0.60)
THREADS=(1 2 4 8)
GF16=(0 1)
STREAM_EVERY=(2 4 8 16)
ADAPT_RS=(0 1)
if (( COMPACT && ! FAST )); then
  # Short default profile: representative, fast, still mode/loss/feature-complete.
  MODES=(normal streaming extreme)
  LOSSES=(0.0 0.10 0.30)
  THREADS=(1 4 8)
  GF16=(0 1)
  STREAM_EVERY=(4 16)
  ADAPT_RS=(0 1)
fi
if (( FAST )); then
  # Minimal quick profile.
  MODES=(normal streaming)
  LOSSES=(0.0 0.05 0.20)
  THREADS=(2)
  GF16=(0)
  STREAM_EVERY=(8)
  ADAPT_RS=(0)
fi

# Result accumulators
TOTAL=0; PASS=0; FAIL=0

RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "fec_simulation"; JSON_FIRST_RUN=1
RAW="$OUTPUT_DIR/raw.tsv"; : > "$RAW" # mode\tloss\tthreads\tgf16\tstream_every\tadapt_rs\tok

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
  local mode="$1" loss="$2" th="$3" use_gf16="$4" stream_every="$5" adapt_rs="$6"
  local tag="mode=${mode},loss=${loss},threads=${th},gf16=${use_gf16}"
  local envs=(
    "QUICFUSCATE_FEC_INITIAL_MODE=${mode}"
    "QUICFUSCATE_RS_LOSS=${loss}"
    "QUICFUSCATE_RAYON_THREADS=${th}"
  )
  if [[ "$use_gf16" == "1" ]]; then envs+=("QUICFUSCATE_GF16_SIMD=1" "QUICFUSCATE_GF16_NIBBLE=1"); fi
  if [[ -n "${stream_every}" ]]; then envs+=("QUICFUSCATE_FEC_STREAM_EVERY=${stream_every}"); fi
  if [[ "$adapt_rs" == "1" ]]; then envs+=("QUICFUSCATE_FEC_ADAPT_RS=1"); fi
  if [[ -n "$RUSTFLAGS_EXTRA" ]]; then envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}"); fi

  echo -e "\n> ${tag}" | tee -a "$LOG_FILE"
  local start=$(date +%s)

  # Cargo accepts a single test-name filter; use an adaptive FEC core-path test
  # per matrix cell to validate env-driven behavior without invalid multi-filter args.
  local command_status=0
  if run_cargo_logged "${envs[@]}" -- \
      test --release --lib 'fec::test_auto_mode_streaming_selection' -- --nocapture \
      >>"$LOG_FILE" 2>&1; then
    ok=1
  else
    command_status=$?
    ok=0
  fi
  local result="PASS"; local reason=""
  if (( ! ok )); then
    result="FAIL"
    reason="cargo_test_failed"
  fi

  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1)); if (( ok )); then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

  # JSON line
  # Raw line for post-matrix
  echo -e "${mode}\t${loss}\t${th}\t${use_gf16}\t${stream_every}\t${adapt_rs}\t${ok}" >> "$RAW"
  qf_json_append_object "$RESULTS_JSON" "mode=$mode" "loss=float:$loss" "threads=int:$th" \
    "gf16=int:$use_gf16" "stream_every=int:$stream_every" "adapt_rs=int:$adapt_rs" \
    "duration_sec=int:$dur" "ok=int:$ok" "result=$result" "reason=$reason" \
    "argv=json:$(qf_json_array cargo test --release --lib fec::test_auto_mode_streaming_selection -- --nocapture)" \
    "environment=json:$(qf_json_environment_with_assignments "${envs[@]}" "CARGO_FEATURES=$(qf_cargo_test_feature_set "$CARGO_FEATURES")")" \
    "command_status=int:$command_status"
}

if (( COMPACT )); then
  # Compact coverage mode:
  # 1) Full mode x loss grid with baseline toggles.
  # 2) Focused sweeps to cover thread/gf16/stream/adapt knobs.
  baseline_threads=2
  baseline_gf16=0
  baseline_stream_every=8
  baseline_adapt_rs=0

  for m in "${MODES[@]}"; do
    for l in "${LOSSES[@]}"; do
      run_one "$m" "$l" "$baseline_threads" "$baseline_gf16" "$baseline_stream_every" "$baseline_adapt_rs"
    done
  done

  # Thread scaling sweep at representative mid loss.
  rep_loss_threads=0.10
  for t in "${THREADS[@]}"; do
    run_one "normal" "$rep_loss_threads" "$t" "$baseline_gf16" "$baseline_stream_every" "$baseline_adapt_rs"
  done

  # GF16 toggle sweep on representative losses.
  for l in 0.10 0.30; do
    for g in "${GF16[@]}"; do
      run_one "normal" "$l" "$baseline_threads" "$g" "$baseline_stream_every" "$baseline_adapt_rs"
    done
  done

  # Streaming cadence sweep.
  for se in "${STREAM_EVERY[@]}"; do
    run_one "streaming" 0.15 "$baseline_threads" "$baseline_gf16" "$se" "$baseline_adapt_rs"
  done

  # Adaptive RS toggle sweep.
  for ar in "${ADAPT_RS[@]}"; do
    run_one "normal" 0.30 "$baseline_threads" "$baseline_gf16" "$baseline_stream_every" "$ar"
  done
else
  for m in "${MODES[@]}"; do
    for l in "${LOSSES[@]}"; do
      for t in "${THREADS[@]}"; do
        for g in "${GF16[@]}"; do
          for se in "${STREAM_EVERY[@]}"; do
            for ar in "${ADAPT_RS[@]}"; do
              run_one "$m" "$l" "$t" "$g" "$se" "$ar"
            done
          done
        done
      done
    done
  done
fi

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Simulation Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total runs:  $TOTAL" | tee -a "$LOG_FILE"
echo "  [OK] Passed:    $PASS" | tee -a "$LOG_FILE"
echo "  [FAIL] Failed:    $FAIL" | tee -a "$LOG_FILE"
echo "  Artifacts:   $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "  Proof scope: all cells run fec::test_auto_mode_streaming_selection under different" | tee -a "$LOG_FILE"
echo "               runtime environments. Green means configuration robustness, not" | tee -a "$LOG_FILE"
echo "               per-dimension path coverage." | tee -a "$LOG_FILE"

# Build a success matrix by (mode,loss)
MATRIX_TSV="$OUTPUT_DIR/matrix.tsv"
awk -F"\t" '{ key=$1"\t"$2; total[key]++; pass[key]+=$7 } END { for (k in total) { p=pass[k]; f=total[k]-p; rate=(total[k]>0)?(p*100/total[k]):0; printf "%s\t%d\t%d\t%.1f\n", k, p, f, rate } }' "$RAW" \
  | sort -k1,1 -k2,2n > "$MATRIX_TSV"

# Emit matrix.json (simple)
MATRIX_JSON="$OUTPUT_DIR/matrix.json"
MATRIX_DOCUMENT="$(python3 - "$MATRIX_TSV" <<'PY'
import json
import sys
from pathlib import Path

matrix = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    mode, loss, passed, failed, rate = line.split("\t")
    matrix[f"{mode}_{loss}"] = {
        "mode": mode,
        "loss": float(loss),
        "pass": int(passed),
        "fail": int(failed),
        "success_rate": float(rate),
    }
document = {
    "schema": "quicfuscate.v1.fec_simulation_matrix",
    "test_under_matrix": "fec::test_auto_mode_streaming_selection",
    "proof_boundary": "Every cell runs the same focused test under a different runtime environment. A green matrix proves configuration robustness, not per-dimension code-path coverage.",
    "matrix": matrix,
}
print(json.dumps(document, ensure_ascii=False, separators=(",", ":")))
PY
)"
qf_json_write_raw_file "$MATRIX_JSON" "$MATRIX_DOCUMENT"

# fec_sim e2e tests moved to test-fec-e2e-loss.sh (TODO-370)

exit $(( FAIL > 0 ))
