#!/usr/bin/env bash
# Description: Analysis helper: analysis-coverage-summary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --dry-run) DRY_RUN=1;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--fast|--full] [--dry-run]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "analysis_coverage"; JSON_FIRST_RUN=1

MODE="full"
(( FAST )) && MODE="fast"
if (( FAST )); then
  COVERAGE_BACKEND="static-function-test-inventory"
elif command -v cargo-llvm-cov >/dev/null 2>&1; then
  COVERAGE_BACKEND="cargo-llvm-cov-summary"
else
  COVERAGE_BACKEND="cargo-test-function-inventory"
fi

append_mode_metadata() {
  printf '  {"cell":"meta","result":"PASS","reason":"","command":"","command_status":0,"meta":{"mode":"%s","fast":%s,"selected_cells":["%s"],"cell_count":1,"backend":"%s"}}' \
    "$MODE" "$FAST" "$COVERAGE_BACKEND" "$COVERAGE_BACKEND" >> "$RESULTS_JSON"
  JSON_FIRST_RUN=0
}

append_mode_metadata
if (( DRY_RUN )); then
  echo "DRY-RUN: mode=$MODE backend=$COVERAGE_BACKEND"
  echo "," >> "$RESULTS_JSON"
  echo '  {"cell":"dry-run","result":"SKIP","reason":"dry_run","command_status":null}' >> "$RESULTS_JSON"
  json_end "$RESULTS_JSON"
  echo "Artifacts: $OUTPUT_DIR"
  exit 0
fi

echo "==============================================================="
if (( FAST )); then
  echo "  Fast Coverage Proxy Summary"
else
  echo "  Coverage Summary"
fi
echo "==============================================================="

if (( FAST )); then
  info "Fast mode: static function/test inventory (no Cargo coverage run)"
  require_cmd rg
  total_fns=$(rg -N "^\s*(pub\s+)?(async\s+)?fn\s+" src -n --color=never | wc -l | tr -d ' ')
  test_fns=$(rg -N "#\[(tokio:)?test\b" src scripts/tests/rust -n --color=never | wc -l | tr -d ' ')
  echo "Total functions: $total_fns" | tee "$OUTPUT_DIR/coverage.txt"
  echo "Test functions:  $test_fns" | tee -a "$OUTPUT_DIR/coverage.txt"
  echo "," >> "$RESULTS_JSON"
  printf '  {"cell":"static-function-test-inventory","mode":"fast","result":"PASS","reason":"","command":"rg function and test inventory","command_status":0,"total_functions":%s,"test_functions":%s}' \
    "$total_fns" "$test_fns" >> "$RESULTS_JSON"
elif command -v cargo-llvm-cov >/dev/null 2>&1; then
  info "Using cargo-llvm-cov"
  run cargo llvm-cov clean --workspace
  run cargo llvm-cov --summary-only --workspace --lcov --output-path "$OUTPUT_DIR/lcov.info"
  run cargo llvm-cov report --summary-only --workspace | tee "$OUTPUT_DIR/coverage.txt"
  # Append a JSON item with the summary line
  if [[ -f "$OUTPUT_DIR/coverage.txt" ]]; then
    summary=$(tail -n 1 "$OUTPUT_DIR/coverage.txt" | sed 's/"/\"/g')
    if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
    echo -n '  {"cell":"coverage-summary","mode":"full","backend":"cargo-llvm-cov-summary","result":"PASS","summary":'"\"$summary\""'}' >> "$RESULTS_JSON"
  fi
else
  warn "cargo-llvm-cov not installed; falling back to simple stats"
  run_cargo test --quiet
  require_cmd rg
  # Simple proxy metric: ratio of test fns to total fns
  total_fns=$(rg -N "^\s*(pub\s+)?(async\s+)?fn\s+" src -n --color=never | wc -l | tr -d ' ')
  test_fns=$(rg -N "#\[(tokio::)?test\b" src scripts/tests/rust -n --color=never | wc -l | tr -d ' ')
  echo "Total functions: $total_fns" | tee "$OUTPUT_DIR/coverage.txt"
  echo "Test functions:  $test_fns" | tee -a "$OUTPUT_DIR/coverage.txt"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"cell":"static-function-test-inventory","mode":"full","backend":"cargo-test-function-inventory","result":"PASS","total_functions":'"$total_fns"',"test_functions":'"$test_fns"'}' >> "$RESULTS_JSON"
fi

echo -e "\nArtifacts: $OUTPUT_DIR"
json_end "$RESULTS_JSON"
