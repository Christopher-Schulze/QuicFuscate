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
  printf '  {"cell":"meta","result":"PASS","reason":"","command":"","command_status":0,"meta":{"mode":"%s","fast":%s,"selected_cells":%s,"cell_count":%s}}' \
    "$mode" "$FAST" "$cells_json" "${#SELECTED_CELLS[@]}" >> "$JSON"
  JSON_FIRST_RUN=0
}

append_mode_metadata
if (( DRY_RUN )); then
  echo "DRY-RUN: mode=$([[ "$FAST" -eq 1 ]] && echo fast || echo full) cells=${SELECTED_CELLS[*]}"
  echo "," >> "$JSON"
  echo '  {"cell":"dry-run","result":"SKIP","reason":"dry_run","command_status":null}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

echo "==============================================================="
echo "  Optimization & Hardware Acceleration Benchmarks"
echo "==============================================================="

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping optimization benches."
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

run_cargo build --release --features "${CARGO_FEATURES:-benches}"

for cell in "${SELECTED_CELLS[@]}"; do
  case "$cell" in
    sort_simd) echo -e "\n> Benchmarking SIMD Sort (u32)...";;
    sort_simd/1024_elems) echo -e "\n> Benchmarking SIMD Sort (u32, fast cell)...";;
    shuffle_simd) echo -e "\n> Benchmarking SIMD Shuffle...";;
  esac
  run cargo bench --features benches -- "$cell"
done

echo -e "\n[OK] Optimization Benchmarks Complete"
json_end "$JSON"
