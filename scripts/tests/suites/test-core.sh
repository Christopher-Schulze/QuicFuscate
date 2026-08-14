#!/usr/bin/env bash
# Description: Test suite runner: test-core.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
ONLY="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --only) ONLY="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--only cli,core,interface,telemetry,reality] [options]"; echo "Core Integration Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

validate_scope_selection() {
  qf_validate_scope_selection "$ONLY" "cli,core,interface,telemetry,reality"
}

scope_selected() {
  qf_scope_selected "$ONLY" "$1"
}

validate_scope_selection

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-core-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/core-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_core_integration"; JSON_FIRST_RUN=1

qf_json_append_object "$JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "selected_scopes=$ONLY" \
  "command_status=int:0" \
  "raw_output="

record_scope_skip() {
  local scope="$1"
  qf_json_append_object "$JSON" \
    "name=scope-$scope" \
    "status=SKIP" \
    "result=SKIP" \
    "reason=not_selected_by_scope" \
    "command_status=int:0" \
    "raw_output="
}

for scope in cli core interface telemetry reality; do
  if ! scope_selected "$scope"; then
    record_scope_skip "$scope"
  fi
done

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
  local command_status=0
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
  else
    command_status="$?"
  fi
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

write_interface_platform_negative_proof() {
  local host_os="$(detect_os)"
  local host_arch="$(detect_arch)"
  local linux_name_status="SKIP"
  local linux_name_reason="host_os_not_linux"
  local macos_iovec_status="SKIP"
  local macos_iovec_reason="host_os_not_macos"
  local wintun_deterministic_status="SKIP"
  local wintun_deterministic_reason="host_os_not_windows_cleanup_state_is_target_gated"
  local bmi2_dispatch_status="SKIP"
  local bmi2_dispatch_reason="host_arch_not_x86_64"
  local bmi2_native_status="SKIP"
  local bmi2_native_reason="host_arch_not_x86_64_or_host_cpu_has_no_bmi2"

  case "$host_os" in
    windows)
      wintun_deterministic_status="PASS"
      wintun_deterministic_reason="windows_cleanup_state_and_send_sync_targets_executed"
      ;;
    linux)
      linux_name_status="PASS"
      linux_name_reason="linux_compatibility_kernel_name_test_executed"
      ;;
    macos)
      macos_iovec_status="PASS"
      macos_iovec_reason="macos_utun_iovec_test_executed"
      ;;
  esac

  if [[ "$host_arch" == "x86_64" ]]; then
    bmi2_dispatch_status="PASS"
    bmi2_dispatch_reason="synthetic_profile_intersection_tests_executed"
    if host_has_bmi2; then
      bmi2_native_status="PASS"
      bmi2_native_reason="native_bmi2_test_executed"
    fi
  fi

  qf_json_write_object_file "$OUTPUT_DIR/interface-platform-negative-proof.json" \
    "schema=quicfuscate.interface_platform_negative_proof.v1" \
    "status=PASS" \
    "source_revision=$(git rev-parse HEAD)" \
    "host_os=$host_os" \
    "host_arch=$host_arch" \
    "generic_interface_status=PASS" \
    "generic_interface_reason=exact_external_factory_fault_targets_executed" \
    "linux_name_status=$linux_name_status" \
    "linux_name_reason=$linux_name_reason" \
    "macos_iovec_status=$macos_iovec_status" \
    "macos_iovec_reason=$macos_iovec_reason" \
    "wintun_deterministic_status=$wintun_deterministic_status" \
    "wintun_deterministic_reason=$wintun_deterministic_reason" \
    "wintun_native_cleanup_fault_status=UNAVAILABLE" \
    "wintun_native_cleanup_fault_reason=requires_windows_win32_fault_injection_verified_dll_and_administrator" \
    "wfp_deterministic_status=UNAVAILABLE" \
    "wfp_deterministic_reason=windows_only_wfp_module_is_not_built_on_this_host" \
    "wfp_native_cleanup_fault_status=UNAVAILABLE" \
    "wfp_native_cleanup_fault_reason=requires_windows_bfe_fault_injection_and_elevated_residue_probe" \
    "bmi2_dispatch_status=$bmi2_dispatch_status" \
    "bmi2_dispatch_reason=$bmi2_dispatch_reason" \
    "bmi2_native_status=$bmi2_native_status" \
    "bmi2_native_reason=$bmi2_native_reason"
  qf_json_append_object "$JSON" \
    "name=interface-platform-negative-proof" \
    "status=PASS" \
    "result=PASS" \
    "reason=local_negative_contracts_executed_and_unavailable_native_lanes_declared" \
    "target=proof-manifest" \
    "feature_set=rust-tests" \
    "command_status=int:0" \
    "raw_output=$OUTPUT_DIR/interface-platform-negative-proof.json"
}

if scope_selected cli; then
  run_cargo test --release --test rt-cli-help -- --nocapture
  run_cargo test --release --test rt-harness-cli -- --nocapture
fi

if scope_selected core; then
  run_cargo test --release --test rt-core-connection-basics -- --nocapture
fi

if scope_selected interface; then
  run_cargo test --release --test rt-interface -- --nocapture
  run_verified_library_target "interface-unaligned-write" \
    "interface::tests::write_packet_accepts_intentionally_unaligned_ipv4_slice" rust-tests
  run_verified_library_target "interface-read-result-contract" \
    "interface::tests::external_factory_read_result_contract_rejects_zero_and_oversized_lengths" rust-tests
  run_verified_library_target "interface-write-result-contract" \
    "interface::tests::external_factory_write_result_contract_rejects_zero_short_and_oversized_results" rust-tests
  run_verified_library_target "interface-write-packet-result-contract" \
    "interface::tests::write_packet_rejects_short_external_factory_result" rust-tests
  run_verified_library_target "unix-raw-result-contract" \
    "interface::tests::unix_raw_result_contract_rejects_zero_and_oversized_counts" rust-tests
  run_verified_library_target "unix-interface-name-contract" \
    "interface::tests::unix_interface_name_parser_requires_bounded_terminated_utf8" rust-tests
  run_verified_library_target "unix-close-ownership" \
    "interface::tests::unix_close_failure_is_reported_and_descriptor_number_is_terminalized" rust-tests
  run_verified_library_target "compatibility-tun-handle-close" \
    "implementations::client::platform::traits::tests::tun_handle_close_failure_is_reported_and_terminalized" rust-tests
  if [[ "$(detect_os)" == "windows" ]]; then
    run_verified_library_target "wintun-cleanup-state" \
      "interface::wintun::tests::wintun_cleanup_state_retains_failed_resources_for_retry" rust-tests
  else
    record_platform_skip "wintun-cleanup-state" "host_os_not_windows" "lib" "rust-tests"
  fi
  run_verified_library_target "wintun-send-sync-contract" \
    "interface::wintun::tests::wintun_device_send_sync_contract_is_compile_checked" rust-tests
  case "$(detect_os)" in
    macos)
      run_verified_library_target "macos-utun-iovec-contract" \
        "interface::macos_tun::tests::utun_writev_iovecs_follow_bounded_progress" rust-tests
      record_platform_skip "linux-compatibility-kernel-name" "host_os_not_linux" "lib" "rust-tests"
      ;;
    linux)
      run_verified_library_target "linux-compatibility-kernel-name" \
        "implementations::client::platform::linux::tests::compatibility_kernel_name_contract_rejects_unterminated_identity" rust-tests
      record_platform_skip "macos-utun-iovec-contract" "host_os_not_macos" "lib" "rust-tests"
      ;;
    *)
      record_platform_skip "linux-compatibility-kernel-name" "host_os_not_linux" "lib" "rust-tests"
      record_platform_skip "macos-utun-iovec-contract" "host_os_not_macos" "lib" "rust-tests"
      ;;
  esac
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
  write_interface_platform_negative_proof
fi

if scope_selected core; then
  run_cargo test --release --test rt-compress-preprocessor -- --nocapture
fi

if scope_selected telemetry; then
  run_cargo test --release --test rt-telemetry-http -- --nocapture
  run_cargo test --release --test rt-profile-aegis-selection -- --nocapture
  run_cargo test --release --test rt-qftls-profiles -- --nocapture
  run_cargo test --release --test rt-admin-http-contract -- --nocapture
fi

if scope_selected reality; then
  run_cargo test --release --test rt-reality-targets -- --nocapture
fi

echo -e "\n[OK] Core Integration Tests Complete"
json_end "$JSON"
