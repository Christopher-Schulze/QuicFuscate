#!/usr/bin/env bash
# Description: Contract test: dynamic Cargo test discovery fails closed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR]"
      echo "Proves that Cargo discovery failure, target mismatch, stale filters, and zero-test runs are non-pass results."
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
  shift
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-dynamic-discovery.XXXXXX")"
else
  mkdir -p "$OUTPUT_DIR"
fi

RESULTS_JSON="$OUTPUT_DIR/results.json"
json_begin "$RESULTS_JSON" "tests_dynamic_discovery_contract"
JSON_FIRST_RUN=1

append_probe() {
  local name="$1" result="$2" reason="$3" legacy_status="$4"
  local output_file="$5"
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  printf '  {"name":"%s","status":"%s","result":"%s","reason":"%s","command":"%s","target":"%s","feature_set":"%s","filter":"%s","test_count":%s,"command_status":%s,"raw_output":"%s"}' \
    "$(qf_json_escape "$name")" "$(qf_json_escape "$legacy_status")" "$(qf_json_escape "$result")" \
    "$(qf_json_escape "$reason")" "$(qf_json_escape "$QF_CARGO_TEST_COMMAND")" \
    "$(qf_json_escape "$QF_CARGO_TEST_TARGET")" "$(qf_json_escape "$QF_CARGO_TEST_FEATURE_SET")" \
    "$(qf_json_escape "$QF_CARGO_TEST_FILTER")" "$QF_CARGO_TEST_COUNT" "$QF_CARGO_TEST_COMMAND_STATUS" \
    "$(qf_json_escape "$output_file")" >> "$RESULTS_JSON"
}

run_discovery_probe() {
  local name="$1" expected_status="$2" output_file="$3" target="$4" feature_set="$5"
  shift 5
  local command_status=0
  if qf_cargo_test_discover "$output_file" "$target" "$feature_set" "$@"; then
    command_status=0
  else
    command_status=$?
  fi
  [[ "$QF_CARGO_TEST_STATUS" == "$expected_status" ]] || die "$name expected $expected_status, got $QF_CARGO_TEST_STATUS"
  append_probe "$name" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
    "$([[ "$QF_CARGO_TEST_STATUS" == "PASS" ]] && echo ok || echo fail)" "$output_file"
  if [[ "$expected_status" == "PASS" ]]; then
    [[ "$command_status" -eq 0 ]] || die "$name returned a nonzero status for PASS"
  else
    [[ "$command_status" -ne 0 ]] || die "$name returned zero for non-pass result"
  fi
}

run_execution_probe() {
  local name="$1" expected_status="$2" output_file="$3" target="$4" feature_set="$5" filter="$6"
  shift 6
  local command_status=0
  if qf_cargo_test_run "$output_file" "$target" "$feature_set" "$filter" "$@"; then
    command_status=0
  else
    command_status=$?
  fi
  [[ "$QF_CARGO_TEST_STATUS" == "$expected_status" ]] || die "$name expected $expected_status, got $QF_CARGO_TEST_STATUS"
  append_probe "$name" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
    "$([[ "$QF_CARGO_TEST_STATUS" == "PASS" ]] && echo ok || echo fail)" "$output_file"
  if [[ "$expected_status" == "PASS" ]]; then
    [[ "$command_status" -eq 0 ]] || die "$name returned a nonzero status for PASS"
  else
    [[ "$command_status" -ne 0 ]] || die "$name returned zero for non-pass result"
  fi
}

run_discovery_probe "positive_lib_discovery" "PASS" "$OUTPUT_DIR/positive-lib-list.txt" \
  "lib" "rust-tests" --release --lib
[[ "$QF_CARGO_TEST_COUNT" -gt 0 ]] || die "positive discovery returned zero tests"

export RUSTFLAGS_EXTRA="-Z quicfuscate_dynamic_discovery_failure"
run_discovery_probe "discovery_command_failure" "FAIL" "$OUTPUT_DIR/failing-list.txt" \
  "lib" "rust-tests" --release --lib
[[ "$QF_CARGO_TEST_COMMAND_STATUS" -ne 0 ]] || die "discovery failure lost its nonzero command status"
unset RUSTFLAGS_EXTRA

run_discovery_probe "integration_target_discovery" "PASS" "$OUTPUT_DIR/integration-list.txt" \
  "test:rt-probe-detection" "rust-tests" --release --features rust-tests --test rt-probe-detection
[[ "$QF_CARGO_TEST_COUNT" -gt 0 ]] || die "integration discovery returned zero tests"

run_execution_probe "target_mismatch_zero_test" "FAIL" "$OUTPUT_DIR/target-mismatch.txt" \
  "lib" "rust-tests" "benign_packet_is_not_flagged_as_probe" \
  --release --features rust-tests --lib benign_packet_is_not_flagged_as_probe -- --nocapture
[[ "$QF_CARGO_TEST_COUNT" -eq 0 ]] || die "target mismatch unexpectedly executed a library test"

run_discovery_probe "stale_pattern_discovery" "FAIL" "$OUTPUT_DIR/stale-list.txt" \
  "lib" "rust-tests" --release --features rust-tests --lib \
  quicfuscate_stale_dynamic_discovery_pattern
[[ "$QF_CARGO_TEST_COUNT" -eq 0 ]] || die "stale pattern discovery reported tests"

run_execution_probe "zero_test_execution" "FAIL" "$OUTPUT_DIR/zero-test-run.txt" \
  "lib" "rust-tests" "quicfuscate_zero_test_dynamic_discovery_pattern" \
  --release --features rust-tests --lib quicfuscate_zero_test_dynamic_discovery_pattern -- --nocapture
[[ "$QF_CARGO_TEST_COUNT" -eq 0 ]] || die "zero-test execution reported tests"

json_end "$RESULTS_JSON"
echo "[PASS] dynamic discovery fail-closed contract: result=$RESULTS_JSON"
