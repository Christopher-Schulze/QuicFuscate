#!/usr/bin/env bash
# Description: Test suite runner: test-core.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Core Integration Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-core-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/core-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_core_integration"; JSON_FIRST_RUN=1

if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi

echo "==============================================================="
echo "  Core Integration Test Suite"
echo "==============================================================="

record_platform_skip() {
  local name="$1"
  local reason="$2"
  local target="${3:-not_applicable}"
  local feature_set="${4:-rust-tests}"
  qf_json_append_object "$JSON" \
    "name=$name" \
    "status=SKIP" \
    "result=SKIP" \
    "reason=$reason" \
    "target=$target" \
    "feature_set=$feature_set" \
    "command_status=int:0" \
    "raw_output="
  echo "[SKIP] $name: $reason"
}

run_verified_library_target() {
  local name="$1"
  local expected_test_name="$2"
  local feature_set="$3"
  local output_file="$OUTPUT_DIR/${name}.log"
  if qf_cargo_test_run_expect \
    "$output_file" "lib" "$feature_set" "$expected_test_name" "$expected_test_name" \
    --release --lib "$expected_test_name" -- --nocapture --exact; then
    qf_json_append_object "$JSON" \
      "name=$name" \
      "status=PASS" \
      "result=PASS" \
      "reason=expected_library_test_executed" \
      "target=lib" \
      "feature_set=$(qf_cargo_test_feature_set "$feature_set")" \
      "test_count=int:$QF_CARGO_TEST_COUNT" \
      "command_status=int:0" \
      "raw_output=$output_file"
    return 0
  fi
  local command_status="$?"
  qf_json_append_object "$JSON" \
    "name=$name" \
    "status=FAIL" \
    "result=FAIL" \
    "reason=$QF_CARGO_TEST_REASON" \
    "target=$QF_CARGO_TEST_TARGET" \
    "feature_set=$QF_CARGO_TEST_FEATURE_SET" \
    "test_count=int:$QF_CARGO_TEST_COUNT" \
    "command_status=int:$command_status" \
    "raw_output=$output_file"
  return "$command_status"
}

host_has_bmi2() {
  case "$(detect_os)" in
    macos)
      [[ "$(sysctl -n hw.optional.bmi2_0 2>/dev/null || printf '0')" == "1" ]]
      ;;
    linux)
      if [[ -r /proc/cpuinfo ]] && grep -Eiq '(^|[[:space:]])bmi2([[:space:]]|$)' /proc/cpuinfo; then
        return 0
      fi
      lscpu 2>/dev/null | grep -Eiq 'Flags:.*(^|[[:space:]])bmi2([[:space:]]|$)'
      ;;
    *)
      return 1
      ;;
  esac
}

run_native_bmi2_interface_test() {
  local feature_set="rust-tests"
  local expected_test_name="interface::tests::bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported"
  if [[ "$(detect_arch)" != "x86_64" ]]; then
    record_platform_skip "interface-bmi2-native" "host_arch_not_x86_64" "lib" "$feature_set"
    return 0
  fi
  if ! host_has_bmi2; then
    record_platform_skip "interface-bmi2-native" "host_cpu_has_no_bmi2" "lib" "$feature_set"
    return 0
  fi
  run_verified_library_target "interface-bmi2-native" "$expected_test_name" "$feature_set"
}

# CLI and harness
run_cargo test --release --test rt-cli-help -- --nocapture
run_cargo test --release --test rt-harness-cli -- --nocapture

# Core wiring and config
run_cargo test --release --test rt-core-connection-basics -- --nocapture
run_cargo test --release --test rt-interface -- --nocapture
run_verified_library_target "interface-unaligned-write" \
  "interface::tests::write_packet_accepts_intentionally_unaligned_ipv4_slice" rust-tests
run_verified_library_target "interface-read-result-contract" \
  "interface::tests::external_factory_read_result_contract_rejects_zero_and_oversized_lengths" rust-tests
run_verified_library_target "interface-write-result-contract" \
  "interface::tests::external_factory_write_result_contract_rejects_zero_short_and_oversized_results" rust-tests
run_verified_library_target "interface-write-packet-result-contract" \
  "interface::tests::write_packet_rejects_short_external_factory_result" rust-tests
if [[ "$(detect_arch)" == "x86_64" ]]; then
  run_verified_library_target "interface-bmi2-dispatch" \
    "interface::tests::bmi2_dispatch_requires_profile_and_runtime_feature_intersection" rust-tests
  run_verified_library_target "cpu-profile-bmi2-intersection" \
    "optimize::tests::x86_profile_selection_keeps_bmi2_explicit" rust-tests
else
  record_platform_skip "interface-bmi2-dispatch" "host_arch_not_x86_64" "lib" "rust-tests"
  record_platform_skip "cpu-profile-bmi2-intersection" "host_arch_not_x86_64" "lib" "rust-tests"
fi
run_native_bmi2_interface_test
run_cargo test --release --test rt-compress-preprocessor -- --nocapture

# Telemetry + profiles
run_cargo test --release --test rt-telemetry-http -- --nocapture
run_cargo test --release --test rt-profile-aegis-selection -- --nocapture
run_cargo test --release --test rt-qftls-profiles -- --nocapture
run_cargo test --release --test rt-admin-http-contract -- --nocapture

# Reality fallback
run_cargo test --release --test rt-reality-targets -- --nocapture

echo -e "\n[OK] Core Integration Tests Complete"
json_end "$JSON"
