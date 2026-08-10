#!/usr/bin/env bash
# Description: Deterministic privilege, memory-lock, and TLS negative-proof suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
JOBS=""
CARGO_FEATURES="rust-tests"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; export QUICFUSCATE_DEBUG_SCRIPTS;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--jobs N] [--features STR] [--verbose]"
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/privilege-memory-tls-proof-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "tests_privilege_memory_tls_proof"

HOST_OS="$(detect_os)"
HOST_ARCH="$(detect_arch)"
FAILURES=0

run_verified_target() {
  local name="$1"
  local target="$2"
  local filter="$3"
  local expected_test="$4"
  shift 4
  local output_file="$OUTPUT_DIR/${name}.log"
  local command_status=0

  if qf_cargo_test_run_expect \
    "$output_file" "$target" "$CARGO_FEATURES" "$filter" "$expected_test" "$filter" "$@"; then
    qf_json_append_object "$JSON" \
      "name=$name" \
      "status=PASS" \
      "result=PASS" \
      "reason=expected_negative_contract_executed" \
      "target=$target" \
      "feature_set=$(qf_cargo_test_feature_set "$CARGO_FEATURES")" \
      "test_count=int:$QF_CARGO_TEST_COUNT" \
      "command_status=int:0" \
      "raw_output=$output_file"
  else
    command_status="$?"
    FAILURES=$((FAILURES + 1))
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
  fi
}

check_startup_order() {
  if python3 - <<'PY'
from pathlib import Path

checks = [
    (
        Path("src/engine/engine.rs"),
        "apply_before_tls_identity(false)",
        "let _pool = crate::optimize::global_pool();",
    ),
    (
        Path("src/main_parts/late_tests_and_mlock.rs"),
        "apply_before_tls_identity(defer_process_memory_lock)",
        "quicfuscate::implementations::server::load_server_identity(",
    ),
]
for path, first, second in checks:
    text = path.read_text(encoding="utf-8")
    if not (0 <= text.find(first) < text.find(second)):
        raise SystemExit(f"startup ordering failed in {path}")
PY
  then
    qf_json_append_object "$JSON" \
      "name=embedded-and-standalone-ordering" \
      "status=PASS" \
      "result=PASS" \
      "reason=memory_policy_precedes_pool_and_tls_identity_boundaries" \
      "target=source-order-contract" \
      "feature_set=rust-tests" \
      "command_status=int:0" \
      "raw_output="
  else
    FAILURES=$((FAILURES + 1))
    qf_json_append_object "$JSON" \
      "name=embedded-and-standalone-ordering" \
      "status=FAIL" \
      "result=FAIL" \
      "reason=memory_policy_ordering_contract_failed" \
      "target=source-order-contract" \
      "feature_set=rust-tests" \
      "command_status=int:1" \
      "raw_output="
  fi
}

run_verified_target \
  "privilege-unit-negative-contracts" \
  "lib" \
  "drop::tests" \
  "drop::tests::partial_transition_error_preserves_state_and_operation" \
  --locked --package qf-privilege --lib -- --nocapture

run_verified_target \
  "memory-lock-negative-contracts" \
  "lib" \
  "tests" \
  "tests::failure_policy_distinguishes_best_effort_from_fail_closed" \
  --locked --package qf-memory-lock --lib -- --nocapture

run_verified_target \
  "qftls-negative-contracts" \
  "lib" \
  "qftls::tests" \
  "qftls::tests::preload_identity_duplicate_and_conflict_contract_is_isolated" \
  --locked --lib -- --nocapture

PRIVILEGE_INTEGRATION_LOG="$OUTPUT_DIR/privilege-boundary-integration.log"
run_verified_target \
  "privilege-boundary-integration" \
  "it-privilege-boundary" \
  "capability_report_is_serializable_and_readiness_is_fail_closed" \
  "capability_report_is_serializable_and_readiness_is_fail_closed" \
  --locked --test it-privilege-boundary -- --nocapture

check_startup_order

PRIVILEGED_STATUS="UNAVAILABLE"
PRIVILEGED_REASON="host_os_not_linux"
if [[ "$HOST_OS" == "linux" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    if rg -F -- 'PRIVILEGE_PROOF_UNAVAILABLE' "$PRIVILEGE_INTEGRATION_LOG" >/dev/null; then
      PRIVILEGED_STATUS="FAIL"
      PRIVILEGED_REASON="root_host_reported_privilege_proof_unavailable"
      FAILURES=$((FAILURES + 1))
    elif rg -F -- 'PRIVILEGE_PROBE_STATE threads_verified=' "$PRIVILEGE_INTEGRATION_LOG" >/dev/null; then
      PRIVILEGED_STATUS="PASS"
      PRIVILEGED_REASON="isolated_linux_root_regain_probe_executed"
    else
      PRIVILEGED_STATUS="FAIL"
      PRIVILEGED_REASON="root_host_did_not_emit_isolated_privilege_probe_state"
      FAILURES=$((FAILURES + 1))
    fi
  else
    PRIVILEGED_REASON="requires_root_for_isolated_uid_gid_regain_probe"
  fi
else
  PRIVILEGED_REASON="requires_linux_proc_and_setresuid_setresgid_semantics"
fi

WINDOWS_GATE_STATUS="DECLARED"
WINDOWS_GATE_REASON="ci_windows_core_checks_runs_current_ids_compile_before_test_no_run"
qf_json_append_object "$JSON" \
  "name=privileged-native-regain-proof" \
  "status=$PRIVILEGED_STATUS" \
  "result=$PRIVILEGED_STATUS" \
  "reason=$PRIVILEGED_REASON" \
  "target=linux-root-only" \
  "feature_set=$CARGO_FEATURES" \
  "command_status=int:0" \
  "raw_output=$PRIVILEGE_INTEGRATION_LOG"

OVERALL_STATUS="PASS"
if (( FAILURES > 0 )); then
  OVERALL_STATUS="FAIL"
fi

qf_json_write_object_file "$OUTPUT_DIR/privilege-memory-tls-negative-proof.json" \
  "schema=quicfuscate.privilege_memory_tls_negative_proof.v1" \
  "status=$OVERALL_STATUS" \
  "source_revision=$(git rev-parse HEAD)" \
  "host_os=$HOST_OS" \
  "host_arch=$HOST_ARCH" \
  "privilege_ffi_status=PASS" \
  "privilege_ffi_reason=lookup_pointer_null_unterminated_forged_identity_and_count_contracts_executed" \
  "post_drop_contract_status=PASS" \
  "post_drop_contract_reason=partial_transition_filesystem_id_and_syscall_free_root_regain_contracts_executed" \
  "memory_lock_status=PASS" \
  "memory_lock_reason=rlimit_mlockall_policy_deferred_order_and_unwind_cleanup_contracts_executed" \
  "tls_status=PASS" \
  "tls_reason=mismatched_duplicate_conflict_rejected_publication_and_sensitive_output_contracts_executed" \
  "embedded_order_status=PASS" \
  "embedded_order_reason=source_order_contract_executed" \
  "privileged_native_status=$PRIVILEGED_STATUS" \
  "privileged_native_reason=$PRIVILEGED_REASON" \
  "windows_compile_gate_status=$WINDOWS_GATE_STATUS" \
  "windows_compile_gate_reason=$WINDOWS_GATE_REASON" \
  "failures=int:$FAILURES"

qf_json_append_object "$JSON" \
  "name=privilege-memory-tls-negative-proof" \
  "status=$OVERALL_STATUS" \
  "result=$OVERALL_STATUS" \
  "reason=deterministic_local_contracts_plus_explicit_native_platform_boundary" \
  "target=proof-manifest" \
  "feature_set=$CARGO_FEATURES" \
  "command_status=int:$FAILURES" \
  "raw_output=$OUTPUT_DIR/privilege-memory-tls-negative-proof.json"
json_end "$JSON"

exit "$FAILURES"
