#!/usr/bin/env bash
# Description: Fast test helper: fast-fec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR]"
      echo "Runs each focused FEC filter separately and compiles the benches smoke target."
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fec"; JSON_FIRST_RUN=1

FEC_TEST_FEATURES="benches"
FEC_BENCH_FEATURES="benches"
FEC_FILTERS=("fec::tests::" "gf16" "wiedemann" "streaming")
FOCUSED_EXECUTED_TOTAL=0
FOCUSED_FAILURE=0

append_result() {
  local name="$1"
  local status="$2"
  local requested_filter="$3"
  local feature_set="$4"
  local executed_test_count="$5"
  local command_status="$6"
  local log_name="$7"
  local reason="${8:-}"

  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then
    echo "," >> "$JSON"
  fi
  JSON_FIRST_RUN=0
  printf '  {"name":"%s","status":"%s","requested_filter":"%s","feature_set":"%s","executed_test_count":%s,"command_status":%s,"log":"%s"' \
    "$name" "$status" "$requested_filter" "$feature_set" \
    "$executed_test_count" "$command_status" "$log_name" >> "$JSON"
  if [[ -n "$reason" ]]; then
    printf ',"reason":"%s"' "$reason" >> "$JSON"
  fi
  printf '}' >> "$JSON"
}

result_status() {
  local command_status="$1"
  local executed_test_count="$2"
  local output_file="$3"

  if [[ "$command_status" -eq 127 ]]; then
    echo "UNAVAILABLE"
  elif [[ "$command_status" -ne 0 ]]; then
    echo "FAIL"
  elif [[ "$executed_test_count" -eq 0 ]] || ! rg -q 'test result: ok\.' "$output_file"; then
    echo "FAIL"
  else
    echo "PASS"
  fi
}

failure_reason() {
  local status="$1"
  local command_status="$2"
  local executed_test_count="$3"

  if [[ "$status" == "UNAVAILABLE" ]]; then
    echo "cargo command unavailable"
  elif [[ "$command_status" -ne 0 ]]; then
    echo "focused cargo test returned nonzero"
  elif [[ "$executed_test_count" -eq 0 ]]; then
    echo "requested filter executed zero tests"
  else
    echo "focused cargo test did not report an ok result"
  fi
}

run_focused_filter() {
  local filter="$1"
  local index="$2"
  local log_name="focused-${index}.log"
  local output_file="$OUTPUT_DIR/$log_name"
  local output=""
  local command_status=0
  local executed_test_count=0
  local status=""
  local reason=""

  echo "> Running focused FEC filter: $filter (features=${FEC_TEST_FEATURES},rust-tests)"
  set +e
  output="$(LOG_FILE="" JSON="" CARGO_FEATURES="$FEC_TEST_FEATURES" run_cargo test -q --package quicfuscate --lib -- "$filter" 2>&1)"
  command_status=$?
  set -e
  printf '%s\n' "$output" | tee "$output_file"

  executed_test_count="$(awk '/^[[:space:]]*running [0-9]+ tests?$/ { count = $2 } END { print count + 0 }' "$output_file")"
  status="$(result_status "$command_status" "$executed_test_count" "$output_file")"
  reason="$(failure_reason "$status" "$command_status" "$executed_test_count")"
  if [[ "$status" == "PASS" ]]; then
    reason=""
    echo "[PASS] FEC filter $filter executed $executed_test_count tests"
  else
    echo "[${status}] FEC filter $filter: $reason" >&2
    FOCUSED_FAILURE=1
  fi

  append_result \
    "focused_fec_filter" "$status" "$filter" "${FEC_TEST_FEATURES},rust-tests" \
    "$executed_test_count" "$command_status" "$log_name" "$reason"
  FOCUSED_EXECUTED_TOTAL=$((FOCUSED_EXECUTED_TOTAL + executed_test_count))
  [[ "$status" == "PASS" ]]
}

echo "> Running FEC focused tests"
filter_index=0
for filter in "${FEC_FILTERS[@]}"; do
  filter_index=$((filter_index + 1))
  if run_focused_filter "$filter" "$filter_index"; then
    :
  else
    FOCUSED_FAILURE=1
  fi
done

if [[ "$FOCUSED_FAILURE" -ne 0 ]]; then
  echo "[FAIL] FEC focused tests did not satisfy the non-vacuous fail-closed contract" >&2
  json_end "$JSON"
  exit 1
fi

# Smoke: build benches (no run) to catch bench-only paths. This is a separate
# artifact and never substitutes for the focused unit-test result above.
echo "> Checking benches compile (smoke; features=${FEC_BENCH_FEATURES})"
BENCH_LOG_NAME="bench-compile.log"
BENCH_LOG_FILE="$OUTPUT_DIR/$BENCH_LOG_NAME"
bench_output=""
bench_status=0
set +e
bench_output="$(LOG_FILE="" JSON="" run cargo bench --no-run --features "$FEC_BENCH_FEATURES" 2>&1)"
bench_status=$?
set -e
printf '%s\n' "$bench_output" | tee "$BENCH_LOG_FILE"

bench_result=""
bench_reason=""
if [[ "$bench_status" -eq 127 ]]; then
  bench_result="UNAVAILABLE"
  bench_reason="cargo command unavailable"
elif [[ "$bench_status" -eq 0 ]]; then
  bench_result="PASS"
else
  bench_result="FAIL"
  bench_reason="bench smoke command returned nonzero"
fi
append_result \
  "fec_bench_compile" "$bench_result" "" "$FEC_BENCH_FEATURES" \
  0 "$bench_status" "$BENCH_LOG_NAME" "$bench_reason"

if [[ "$bench_result" != "PASS" ]]; then
  echo "[${bench_result}] FEC bench smoke failed: $bench_reason" >&2
  json_end "$JSON"
  exit 1
fi

echo "[OK] FEC tests complete: ${#FEC_FILTERS[@]} filters, ${FOCUSED_EXECUTED_TOTAL} tests, bench smoke PASS"
json_end "$JSON"
