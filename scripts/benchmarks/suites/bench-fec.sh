#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-fec.
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_fec_all"; JSON_FIRST_RUN=1

if (( FAST )); then
  SELECTED_CELLS=(fec_pipeline)
else
  SELECTED_CELLS=(fec_matrix_mul fec_pipeline)
fi

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
if (( DRY_RUN )); then
  echo "DRY-RUN: mode=$([[ "$FAST" -eq 1 ]] && echo fast || echo full) cells=${SELECTED_CELLS[*]}"
  qf_json_append_object "$JSON" "cell=dry-run" "result=SKIP" "reason=dry_run" "command_status=null"
  json_end "$JSON"
  exit 0
fi

echo "==============================================================="
echo "  FEC Internal Machine-Room Benchmarks"
echo "==============================================================="

# Skip gracefully if no Rust benches present; fallback suggestion
# Absence and build failure are different answers. A nonzero --no-run used to report
# both as "no benches detected", so a compile error produced a green skip and could be
# read as a completed performance check.
BENCH_PREFLIGHT="$(qf_bench_preflight benches)" || {
  echo "[FAIL] declared benchmark targets did not build; refusing to report a skip." >&2
  qf_json_append_object "$JSON" "status=failed" "reason=bench_build_failed"
  json_end "$JSON"
  exit 1
}
if [[ "$BENCH_PREFLIGHT" == "absent" ]]; then
  echo "[SKIP] Cargo declares no benchmark targets; skipping FEC benches."
  qf_json_append_object "$JSON" "status=skipped" "reason=no_bench_targets"
  json_end "$JSON"
  exit 0
fi

run_cargo build --release --features "${CARGO_FEATURES:-benches}"

for cell in "${SELECTED_CELLS[@]}"; do
  case "$cell" in
    fec_matrix_mul) echo -e "\n> Benchmarking GF(256) Matrix Multiply (Reed-Solomon core)...";;
    fec_pipeline) echo -e "\n> Benchmarking FEC Encode/Decode Pipeline (TODO-424)...";;
  esac
  run cargo bench --features benches -- "$cell"
done

echo -e "\n[OK] FEC Benchmarks Complete"
json_end "$JSON"
