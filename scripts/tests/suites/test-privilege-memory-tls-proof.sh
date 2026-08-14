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
REQUIRE_NATIVE_PRIVILEGE=0
ONLY="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --only) ONLY="$2"; shift;;
    --require-native-privilege) REQUIRE_NATIVE_PRIVILEGE=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; export QUICFUSCATE_DEBUG_SCRIPTS;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--jobs N] [--features STR] [--only SCOPES] [--require-native-privilege] [--verbose]"
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

validate_scope_selection() {
  [[ "$ONLY" == "all" ]] && return 0
  local scope
  local -a scopes
  IFS=',' read -r -a scopes <<< "$ONLY"
  [[ "${#scopes[@]}" -gt 0 ]] || {
    echo "--only requires at least one scope" >&2
    return 2
  }
  for scope in "${scopes[@]}"; do
    case "$scope" in
      privilege|memory-lock|qftls|integration|ordering|native-privilege) ;;
      *)
        echo "unknown --only scope: $scope (expected privilege,memory-lock,qftls,integration,ordering,native-privilege)" >&2
        return 2
        ;;
    esac
  done
  if [[ ",$ONLY," == *,all,* ]]; then
    echo "--only=all cannot be combined with another scope" >&2
    return 2
  fi
}

scope_selected() {
  local scope="$1"
  [[ "$ONLY" == "all" || ",$ONLY," == *",$scope,"* ]]
}

validate_scope_selection
if [[ "$REQUIRE_NATIVE_PRIVILEGE" == "1" ]] && ! scope_selected native-privilege; then
  echo "--require-native-privilege requires native-privilege in --only" >&2
  exit 2
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/privilege-memory-tls-proof-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "tests_privilege_memory_tls_proof"

qf_json_append_object "$JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "selected_scopes=$ONLY" \
  "command_status=int:0" \
  "raw_output="

HOST_OS="$(detect_os)"
HOST_ARCH="$(detect_arch)"
FAILURES=0
PRIVILEGE_STATUS="SKIP"
MEMORY_LOCK_STATUS="SKIP"
QFTLS_STATUS="SKIP"
INTEGRATION_STATUS="SKIP"
ORDERING_STATUS="SKIP"

scope_status_reason() {
  case "$1" in
    PASS) printf '%s' "selected_target_executed";;
    FAIL) printf '%s' "selected_target_failed";;
    SKIP) printf '%s' "not_selected_by_scope";;
    *) printf '%s' "unknown_scope_status";;
  esac
}

record_scope_skip() {
  local name="$1"
  local target="$2"
  local feature_set="$3"
  qf_json_append_object "$JSON" \
    "name=$name" \
    "status=SKIP" \
    "result=SKIP" \
    "reason=not_selected_by_scope" \
    "target=$target" \
    "feature_set=$(qf_cargo_test_feature_set "$feature_set")" \
    "test_count=int:0" \
    "command_status=int:0" \
    "raw_output="
}

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
  return "$command_status"
}

run_selected_target() {
  local scope="$1"
  local status_variable="$2"
  local name="$3"
  local target="$4"
  local filter="$5"
  local expected_test="$6"
  shift 6

  if ! scope_selected "$scope"; then
    record_scope_skip "$name" "$target" "$CARGO_FEATURES"
    printf -v "$status_variable" '%s' "SKIP"
    return 0
  fi

  if run_verified_target "$name" "$target" "$filter" "$expected_test" "$@"; then
    printf -v "$status_variable" '%s' "PASS"
  else
    printf -v "$status_variable" '%s' "FAIL"
  fi
  return 0
}

check_startup_order() {
  if ! scope_selected ordering; then
    record_scope_skip "embedded-and-standalone-ordering" "source-order-contract" "$CARGO_FEATURES"
    ORDERING_STATUS="SKIP"
    return 0
  fi
  if python3 - <<'PY'
from pathlib import Path

checks = [
    (
        Path("src/engine/engine.rs"),
        "apply_before_tls_identity(false)",
        "let _pool = crate::optimize::global_pool();",
    ),
    (
        Path("src/main/server.rs"),
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
    ORDERING_STATUS="PASS"
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
    ORDERING_STATUS="FAIL"
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

native_privilege_markers_pass() {
  local output_file="$1"
  grep -Fq -- 'privileged_drop_is_isolated_in_a_subprocess' "$output_file" \
    && grep -Fq -- 'test result: ok. 1 passed; 0 failed;' "$output_file" \
    && grep -Fq -- \
      'PRIVILEGE_PROBE_STATE mode=standard threads_verified=' "$output_file" \
    && grep -Fq -- \
      'PRIVILEGE_PROBE_STATE mode=tokio threads_verified=' "$output_file" \
    && grep -Fq -- \
      'PRIVILEGE_NATIVE_PROOF status=PASS modes=standard,tokio parent_root_preserved=1' \
      "$output_file" \
    && ! grep -Fq -- 'PRIVILEGE_PROOF_UNAVAILABLE' "$output_file"
}

compile_privilege_integration_binary() {
  local messages_file="$OUTPUT_DIR/privileged-native-build.jsonl"
  local errors_file="$OUTPUT_DIR/privileged-native-build.stderr.log"
  local -a cargo_args=(
    test
    --locked
    --test it-privilege-boundary
    --features "$CARGO_FEATURES"
    --no-run
    --message-format=json
  )
  if [[ -n "$JOBS" ]]; then
    cargo_args+=(--jobs "$JOBS")
  fi
  if ! cargo "${cargo_args[@]}" >"$messages_file" 2>"$errors_file"; then
    cat "$errors_file" >&2
    return 1
  fi
  python3 - "$messages_file" <<'PY'
import json
import sys
from pathlib import Path

executables = []
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    if message.get("reason") != "compiler-artifact":
        continue
    target = message.get("target", {})
    executable = message.get("executable")
    if target.get("name") == "it-privilege-boundary" and executable:
        executables.append(executable)
unique = list(dict.fromkeys(executables))
if len(unique) != 1:
    raise SystemExit(
        f"expected exactly one it-privilege-boundary executable, found {len(unique)}"
    )
print(unique[0])
PY
}

run_selected_target \
  privilege PRIVILEGE_STATUS \
  "privilege-unit-negative-contracts" \
  "lib" \
  "drop::tests" \
  "drop::tests::partial_transition_error_preserves_state_and_operation" \
  --locked --package qf-privilege --lib -- --nocapture

run_selected_target \
  memory-lock MEMORY_LOCK_STATUS \
  "memory-lock-negative-contracts" \
  "lib" \
  "tests" \
  "tests::failure_policy_distinguishes_best_effort_from_fail_closed" \
  --locked --package qf-memory-lock --lib

run_selected_target \
  qftls QFTLS_STATUS \
  "qftls-negative-contracts" \
  "lib" \
  "qftls::tests" \
  "qftls::tests::preload_identity_duplicate_and_conflict_contract_is_isolated" \
  --locked --lib -- --nocapture

run_selected_target \
  integration INTEGRATION_STATUS \
  "privilege-boundary-integration" \
  "it-privilege-boundary" \
  "capability_report_is_serializable_and_readiness_is_fail_closed" \
  "capability_report_is_serializable_and_readiness_is_fail_closed" \
  --locked --test it-privilege-boundary -- --nocapture

check_startup_order

PRIVILEGED_STATUS="UNAVAILABLE"
PRIVILEGED_REASON="host_os_not_linux"
PRIVILEGED_COMMAND_STATUS=0
PRIVILEGED_LOG="$OUTPUT_DIR/privileged-native-regain-proof.log"
if ! scope_selected native-privilege; then
  PRIVILEGED_STATUS="SKIP"
  PRIVILEGED_REASON="not_selected_by_scope"
elif [[ "$HOST_OS" == "linux" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    if qf_cargo_test_run \
      "$PRIVILEGED_LOG" "it-privilege-boundary" "$CARGO_FEATURES" \
      "privileged_drop_is_isolated_in_a_subprocess" \
      --locked --test it-privilege-boundary \
      privileged_drop_is_isolated_in_a_subprocess -- --exact --nocapture \
      && native_privilege_markers_pass "$PRIVILEGED_LOG"; then
      PRIVILEGED_STATUS="PASS"
      PRIVILEGED_REASON="isolated_linux_root_regain_probe_executed"
    else
      PRIVILEGED_STATUS="FAIL"
      PRIVILEGED_REASON="root_host_did_not_pass_exact_standard_and_tokio_privilege_proof"
      PRIVILEGED_COMMAND_STATUS=1
      FAILURES=$((FAILURES + 1))
    fi
  elif [[ "$REQUIRE_NATIVE_PRIVILEGE" == "1" ]]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true; then
      PRIVILEGED_STATUS="FAIL"
      PRIVILEGED_REASON="passwordless_sudo_unavailable_for_required_native_privilege_proof"
      PRIVILEGED_COMMAND_STATUS=1
      FAILURES=$((FAILURES + 1))
    else
      if ! PRIVILEGE_TEST_BINARY="$(compile_privilege_integration_binary)"; then
        PRIVILEGED_STATUS="FAIL"
        PRIVILEGED_REASON="privilege_integration_binary_compilation_failed"
        PRIVILEGED_COMMAND_STATUS=1
        FAILURES=$((FAILURES + 1))
      elif [[ -z "$PRIVILEGE_TEST_BINARY" || ! -x "$PRIVILEGE_TEST_BINARY" ]]; then
        PRIVILEGED_STATUS="FAIL"
        PRIVILEGED_REASON="privilege_integration_binary_unavailable"
        PRIVILEGED_COMMAND_STATUS=1
        FAILURES=$((FAILURES + 1))
      else
        set +e
        sudo -n -- "$PRIVILEGE_TEST_BINARY" \
          privileged_drop_is_isolated_in_a_subprocess \
          --exact --nocapture --test-threads=1 \
          2>&1 | tee "$PRIVILEGED_LOG"
        PRIVILEGED_COMMAND_STATUS="${PIPESTATUS[0]}"
        set -e
        if [[ "$PRIVILEGED_COMMAND_STATUS" == "0" ]] \
          && native_privilege_markers_pass "$PRIVILEGED_LOG"; then
          PRIVILEGED_STATUS="PASS"
          PRIVILEGED_REASON="isolated_linux_root_regain_probe_executed_via_sudo"
        else
          PRIVILEGED_STATUS="FAIL"
          PRIVILEGED_REASON="required_standard_or_tokio_privilege_proof_failed"
          FAILURES=$((FAILURES + 1))
        fi
      fi
    fi
  else
    PRIVILEGED_REASON="requires_root_for_isolated_uid_gid_regain_probe"
  fi
elif [[ "$REQUIRE_NATIVE_PRIVILEGE" == "1" ]]; then
  PRIVILEGED_STATUS="FAIL"
  PRIVILEGED_REASON="required_native_privilege_proof_requires_linux"
  PRIVILEGED_COMMAND_STATUS=1
  FAILURES=$((FAILURES + 1))
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
  "command_status=int:$PRIVILEGED_COMMAND_STATUS" \
  "raw_output=$PRIVILEGED_LOG"

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
  "privilege_ffi_status=$PRIVILEGE_STATUS" \
  "privilege_ffi_reason=$(scope_status_reason "$PRIVILEGE_STATUS")" \
  "post_drop_contract_status=$PRIVILEGE_STATUS" \
  "post_drop_contract_reason=$(scope_status_reason "$PRIVILEGE_STATUS")" \
  "portable_integration_status=$INTEGRATION_STATUS" \
  "portable_integration_reason=$(scope_status_reason "$INTEGRATION_STATUS")" \
  "memory_lock_status=$MEMORY_LOCK_STATUS" \
  "memory_lock_reason=$(scope_status_reason "$MEMORY_LOCK_STATUS")" \
  "tls_status=$QFTLS_STATUS" \
  "tls_reason=$(scope_status_reason "$QFTLS_STATUS")" \
  "embedded_order_status=$ORDERING_STATUS" \
  "embedded_order_reason=$(scope_status_reason "$ORDERING_STATUS")" \
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
