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

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping transport benches."
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

BENCH_JOBS=()
[[ -n "$JOBS" ]] && BENCH_JOBS+=("-j" "$JOBS")
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA}"

run_cargo build --release --features "${CARGO_FEATURES:-benches}"

# Benchmark selected transport cells.
for cell in "${SELECTED_CELLS[@]}"; do
  case "$cell" in
    varint) echo -e "\n> Benchmarking Varint Operations...";;
    packet_number) echo -e "\n> Benchmarking Packet Number Encode...";;
  esac
  run cargo bench "${BENCH_JOBS[@]}" --features benches -- "$cell"
done

# Export results
OUTPUT_FILE="$OUTPUT_DIR/transport-bench.json"

echo -e "\n> Exporting results to $OUTPUT_FILE..."
run cargo bench "${BENCH_JOBS[@]}" --features benches --no-run --message-format=json > "$OUTPUT_FILE" 2>&1 || true

echo -e "\n[OK] Transport Benchmarks Complete"
json_end "$JSON"
