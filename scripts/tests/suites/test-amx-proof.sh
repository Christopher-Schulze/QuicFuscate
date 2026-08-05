#!/usr/bin/env bash
# Description: Test suite runner: test-amx-proof.
# shellcheck source=scripts/tests/lib/lib-common.sh
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
BUILD_JOBS="${JOBS:-${CARGO_BUILD_JOBS:-2}}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2;;
    --jobs) BUILD_JOBS="$2"; shift 2;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--jobs N]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
validate_positive_int "cargo jobs" "$BUILD_JOBS" 64
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/amx-proof-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/test-amx-proof.log"
exec > >(tee -a "$LOG_FILE") 2>&1

RESULTS_JSON="$OUTPUT_DIR/results.json"
json_begin "$RESULTS_JSON" "tests_amx_proof"

HOST_ARCH="$(detect_arch)"
HOST_OS="$(detect_os)"
CPU_MODEL="$(cpu_name)"
COMPILER_VERSION="$(rustc --version 2>&1 || printf '%s' unknown)"
SOURCE_REVISION="$(git rev-parse HEAD 2>/dev/null || printf '%s' unknown)"
AMX_RUSTFLAGS="-Ctarget-feature=+amx-tile,+amx-int8"
USE_AMX_TARGET_FEATURES=0
[[ "$HOST_ARCH" == "x86_64" ]] && USE_AMX_TARGET_FEATURES=1
FAILURES=0
UNAVAILABLE=0
DISK_UNAVAILABLE=0

append_item() {
  local name="$1"
  local status="$2"
  local result="$3"
  local reason="$4"
  shift 4
  qf_json_append_object "$RESULTS_JSON" \
    "name=$name" "status=$status" "result=$result" "reason=$reason" "$@"
}

run_cargo_capture() {
  local output_file="$1"
  local use_amx="$2"
  shift 2
  local command_status=0
  set +e
  if [[ "$use_amx" -eq 1 ]]; then
    CARGO_BUILD_JOBS="$BUILD_JOBS" RUSTFLAGS="$AMX_RUSTFLAGS" \
      cargo "$@" >"$output_file" 2>&1
    command_status=$?
  else
    CARGO_BUILD_JOBS="$BUILD_JOBS" RUSTFLAGS="" \
      cargo "$@" >"$output_file" 2>&1
    command_status=$?
  fi
  set -e
  return "$command_status"
}

echo "==============================================================="
echo "  AMX Build and Runtime Proof Lane"
echo "==============================================================="
echo "  Host architecture: $HOST_ARCH"
echo "  Required target features: amx-tile, amx-int8"
echo "  BF16 required: false"
echo "  Cargo jobs: $BUILD_JOBS"

append_item "amx_execution_context" "PASS" "PASS" \
  "execution_context_recorded" "architecture=$HOST_ARCH" "operating_system=$HOST_OS" \
  "cpu=$CPU_MODEL" "compiler=$COMPILER_VERSION" "source_revision=$SOURCE_REVISION" \
  "cargo_jobs=int:$BUILD_JOBS" "required_target_features=json:[\"amx-tile\",\"amx-int8\"]" \
  "bf16_required=bool:false"

COMPILE_LOG="$OUTPUT_DIR/amx-target-compile.log"
if [[ "$USE_AMX_TARGET_FEATURES" -eq 0 ]]; then
  UNAVAILABLE=$((UNAVAILABLE + 1))
  append_item "amx_target_compile" "UNAVAILABLE" "UNAVAILABLE" \
    "host_arch_not_x86_64" "target_features=json:[\"amx-tile\",\"amx-int8\"]" \
    "evidence=$COMPILE_LOG"
  printf '%s\n' "AMX target compilation is unavailable on host architecture $HOST_ARCH" >"$COMPILE_LOG"
elif ! warn_if_low_disk_for_step 2 "AMX target compilation" "$PROJECT_ROOT"; then
  DISK_UNAVAILABLE=1
  UNAVAILABLE=$((UNAVAILABLE + 1))
  append_item "amx_target_compile" "UNAVAILABLE" "UNAVAILABLE" \
    "insufficient_free_disk" "target_features=json:[\"amx-tile\",\"amx-int8\"]" \
    "evidence=$COMPILE_LOG"
else
  if run_cargo_capture "$COMPILE_LOG" 1 test --locked --features rust-tests --test rt-amx-proof --no-run; then
    append_item "amx_target_compile" "PASS" "PASS" \
      "target_features_compiled" "target_features=json:[\"amx-tile\",\"amx-int8\"]" \
      "evidence=$COMPILE_LOG"
  else
    FAILURES=$((FAILURES + 1))
    append_item "amx_target_compile" "FAIL" "FAIL" \
      "cargo_target_feature_compile_failed" "target_features=json:[\"amx-tile\",\"amx-int8\"]" \
      "evidence=$COMPILE_LOG"
  fi
fi

RUNTIME_LOG="$OUTPUT_DIR/amx-capability-runtime.log"
CAPABILITY_SUMMARY=""
if [[ "$FAILURES" -gt 0 || "$DISK_UNAVAILABLE" -eq 1 ]]; then
  UNAVAILABLE=$((UNAVAILABLE + 1))
  printf '%s\n' "AMX capability probe was not run because the compile prerequisite was unavailable or failed" >"$RUNTIME_LOG"
  append_item "amx_capability_probe" "UNAVAILABLE" "UNAVAILABLE" \
    "compile_prerequisite_unavailable" "evidence=$RUNTIME_LOG"
else
  if run_cargo_capture "$RUNTIME_LOG" "$USE_AMX_TARGET_FEATURES" \
    test --locked --features rust-tests --test rt-amx-proof -- --nocapture --test-threads=1; then
    append_item "amx_capability_test" "PASS" "PASS" \
      "machine_readable_capability_test_passed" "evidence=$RUNTIME_LOG"
    set +e
    CAPABILITY_SUMMARY="$(python3 - "$RUNTIME_LOG" <<'PY'
import json
import sys

payload = None
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        marker = "AMX_PROOF_RESULT="
        if marker in line:
            candidate = line.split(marker, 1)[1].strip()
            try:
                value = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                payload = value
                break

if payload is None:
    raise SystemExit(1)
status = payload.get("status")
reason = payload.get("reason")
if status not in {"AVAILABLE", "UNAVAILABLE"} or not isinstance(reason, str):
    raise SystemExit(1)
print(status, reason, json.dumps(payload, separators=(",", ":")))
PY
)"
    capability_parse_status=$?
    set -e
    if [[ "$capability_parse_status" -ne 0 ]]; then
      FAILURES=$((FAILURES + 1))
      append_item "amx_capability_probe" "FAIL" "FAIL" \
        "missing_or_invalid_machine_readable_result" "evidence=$RUNTIME_LOG"
    else
      read -r CAPABILITY_STATUS CAPABILITY_REASON CAPABILITY_JSON <<<"$CAPABILITY_SUMMARY"
      if [[ "$CAPABILITY_STATUS" == "UNAVAILABLE" ]]; then
        UNAVAILABLE=$((UNAVAILABLE + 1))
      fi
      append_item "amx_capability_probe" "$CAPABILITY_STATUS" "$CAPABILITY_STATUS" \
        "$CAPABILITY_REASON" "capability=json:$CAPABILITY_JSON" "evidence=$RUNTIME_LOG"
    fi
  else
    FAILURES=$((FAILURES + 1))
    append_item "amx_capability_test" "FAIL" "FAIL" \
      "machine_readable_capability_test_failed" "evidence=$RUNTIME_LOG"
  fi
fi

SCALAR_LOG="$OUTPUT_DIR/scalar-fallback-proof.log"
EXPECTED_TESTS=(
  test_wiedemann_scalar_telemetry_increments
  test_wiedemann_scratch_storage_is_dimension_bounded_and_resettable
  test_wiedemann_large_system_uses_scalar_fallback
  test_wiedemann_scalar_spmv_matches_reference_for_full_and_partial_matrix_shapes
  test_wiedemann_rejects_invalid_dimensions
  test_wiedemann_scalar_solver_is_concurrent_and_amx_free
)
if [[ "$DISK_UNAVAILABLE" -eq 1 ]]; then
  UNAVAILABLE=$((UNAVAILABLE + 1))
  append_item "scalar_fallback_proof" "UNAVAILABLE" "UNAVAILABLE" \
    "insufficient_free_disk" "evidence=$SCALAR_LOG"
elif run_cargo_capture "$SCALAR_LOG" "$USE_AMX_TARGET_FEATURES" \
  test --locked --features rust-tests --lib test_wiedemann -- --nocapture --test-threads=1; then
  missing_test=0
  for expected_test in "${EXPECTED_TESTS[@]}"; do
    if ! grep -Eq "test ([[:alnum:]_]+::)*${expected_test} \.\.\. ok" "$SCALAR_LOG"; then
      missing_test=1
      break
    fi
  done
  if [[ "$missing_test" -eq 0 ]]; then
    append_item "scalar_fallback_proof" "PASS" "PASS" \
      "parity_concurrency_dimensions_cleanup_and_telemetry_tests_passed" \
      "evidence=$SCALAR_LOG"
  else
    FAILURES=$((FAILURES + 1))
    append_item "scalar_fallback_proof" "FAIL" "FAIL" \
      "expected_wiedemann_proof_test_not_executed" "evidence=$SCALAR_LOG"
  fi
else
  FAILURES=$((FAILURES + 1))
  append_item "scalar_fallback_proof" "FAIL" "FAIL" \
    "scalar_fallback_proof_command_failed" "evidence=$SCALAR_LOG"
fi

OVERALL_STATUS="PASS"
if [[ "$FAILURES" -gt 0 ]]; then
  OVERALL_STATUS="FAIL"
elif [[ "$UNAVAILABLE" -gt 0 ]]; then
  OVERALL_STATUS="UNAVAILABLE"
fi
append_item "amx_proof_summary" "$OVERALL_STATUS" "$OVERALL_STATUS" \
  "failures=$FAILURES unavailable=$UNAVAILABLE" \
  "required_target_features=json:[\"amx-tile\",\"amx-int8\"]" \
  "bf16_required=bool:false"
json_end "$RESULTS_JSON"

echo "AMX_PROOF_STATUS=$OVERALL_STATUS"
echo "AMX_PROOF_RESULTS=$RESULTS_JSON"
echo "Failures: $FAILURES"
echo "Unavailable: $UNAVAILABLE"

if [[ "$OVERALL_STATUS" == "FAIL" ]]; then
  exit 1
fi
if [[ "$OVERALL_STATUS" == "UNAVAILABLE" ]]; then
  exit 2
fi
exit 0
