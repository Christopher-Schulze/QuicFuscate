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

# Skip gracefully if bench harness absent
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
  echo "[SKIP] Cargo declares no benchmark targets; skipping transport benches."
  qf_json_append_object "$JSON" "status=skipped" "reason=no_bench_targets"
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
