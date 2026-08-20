#!/usr/bin/env bash
# Description: Test suite runner: test-fec.
# Canonical contract: --only modes,gf16,refactor,all (default modes,gf16). Legacy --refactor/--refactor-only preserved.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
REFACTOR=0
REFACTOR_ONLY=0
ONLY="all"
ONLY_EXPLICIT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --only)
      ONLY="$2"
      ONLY_EXPLICIT=1
      shift
      ;;
    --only=*)
      ONLY="${1#--only=}"
      ONLY_EXPLICIT=1
      ;;
    --refactor) REFACTOR=1;;
    --refactor-only) REFACTOR=1; REFACTOR_ONLY=1;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "FEC Internal Machine-Room Test Suite"
      echo "  --only SCOPE[,SCOPE]   Select scopes: modes,gf16,refactor,all (default: modes,gf16)"
      echo "  --refactor            Include refactor validation checks (legacy, = modes,gf16,refactor)"
      echo "  --refactor-only       Only run refactor validation checks (legacy, = refactor)"
      usage_common_flags 2>/dev/null || true
      exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

# Conflict rule: explicit --only cannot be combined with legacy --refactor flags
if [[ "$ONLY_EXPLICIT" -eq 1 && ( "$REFACTOR" -eq 1 ) ]]; then
  echo "Conflicting selectors: --only and --refactor/--refactor-only cannot be combined" >&2
  exit 2
fi

# Normalize ONLY
ONLY_RAW="$ONLY"
if [[ "$ONLY" == "all" ]]; then
  ONLY="modes,gf16"
fi
if [[ "$REFACTOR_ONLY" -eq 1 ]]; then
  EFFECTIVE="refactor"
elif [[ "$REFACTOR" -eq 1 ]]; then
  EFFECTIVE="modes,gf16,refactor"
else
  EFFECTIVE="$ONLY"
fi

FEC_SCOPES="modes,gf16,refactor"
if ! qf_validate_scope_selection "$EFFECTIVE" "$FEC_SCOPES"; then
  exit 2
fi

# Detect duplicate scopes in EFFECTIVE
IFS=',' read -r -a _eff_arr <<< "$EFFECTIVE"
declare -A _seen=()
for s in "${_eff_arr[@]}"; do
  if [[ -n "${_seen[$s]:-}" ]]; then
    echo "duplicate scope in selection: $s" >&2
    exit 2
  fi
  _seen[$s]=1
done

should_run_scope() {
  local scope="$1"
  qf_scope_selected "$EFFECTIVE" "$scope"
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-fec-internal-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "${CARGO_FEATURES:-}" "${RUSTFLAGS_EXTRA:-}" "${JOBS:-}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/fec-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fec_comprehensive"; export JSON_FIRST_RUN=1
# Tee stdout/stderr to LOG_FILE
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==============================================================="
echo "  FEC Internal Machine-Room Test Suite"
echo "==============================================================="
echo "  Selection: requested=$ONLY_RAW effective=$EFFECTIVE legacy_refactor=$REFACTOR legacy_refactor_only=$REFACTOR_ONLY"

# Selection record
qf_json_append_object "$JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "requested_scopes=$ONLY_RAW" \
  "effective_scopes=$EFFECTIVE" \
  "legacy_refactor=bool:$([[ $REFACTOR -eq 1 ]] && echo true || echo false)" \
  "legacy_refactor_only=bool:$([[ $REFACTOR_ONLY -eq 1 ]] && echo true || echo false)" \
  "command_status=int:0" \
  "raw_output="

# Pre-execution per-scope records (PASS for selected, SKIP for omitted)
for scope in modes gf16 refactor; do
  if should_run_scope "$scope"; then
    qf_json_append_object "$JSON" \
      "name=scope:$scope" \
      "status=PASS" \
      "result=PASS" \
      "reason=selected" \
      "scope=$scope" \
      "command_status=int:0" \
      "raw_output="
  else
    qf_json_append_object "$JSON" \
      "name=scope:$scope" \
      "status=SKIP" \
      "result=SKIP" \
      "reason=not_selected_by_scope" \
      "scope=$scope" \
      "command_status=int:0" \
      "raw_output="
  fi
done

OVERALL_FAIL=0

run_cargo_logged() {
  local output_file="$1"
  shift
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_cargo_logged requires -- before cargo arguments"; return 2; }
  shift
  local cargo_args=("$@")
  local effective_features
  effective_features="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-}")"
  local cmd_json
  cmd_json="$(qf_cargo_test_command_argv_json "$effective_features" "${cargo_args[@]}")"
  local env_json
  if [[ ${#envs[@]} -gt 0 ]]; then
    env_json="$(qf_json_environment_with_assignments "${envs[@]}")"
  else
    env_json="$(qf_json_environment)"
  fi
  # Run and capture
  mkdir -p "$(dirname "$output_file")"
  : > "$output_file"
  local status=0
  if ! run_cargo_with_env "${envs[@]}" -- "${cargo_args[@]}" >"$output_file" 2>&1; then
    status=$?
  fi
  cat "$output_file"
  # Classify
  local filter="<all>"
  # Extract filter for metadata
  for arg in "${cargo_args[@]}"; do
    case "$arg" in --lib|--release|--quiet|--nocapture) ;; --) break;; *) filter="$arg"; break;; esac
  done
  if [[ "$filter" == "--"* || "$filter" == "" ]]; then filter="<all>"; fi
  # For modes the filter is fec:: or gf16, for refactor it's specific lib filter
  qf_cargo_test_metadata_from_args "${cargo_args[@]}"
  local qf_target="$QF_CARGO_TEST_TARGET"
  local qf_features="$QF_CARGO_TEST_FEATURE_SET"
  local qf_filter="$QF_CARGO_TEST_FILTER"
  qf_cargo_test_classify_output run "$output_file" "$status" "$qf_target" "$qf_features" "$qf_filter" "${cargo_args[*]}" || true
  local test_status="$QF_CARGO_TEST_STATUS"
  local test_reason="$QF_CARGO_TEST_REASON"
  local test_count="$QF_CARGO_TEST_COUNT"
  local result="PASS"
  local reason="$test_reason"
  if [[ "$test_status" != "PASS" ]]; then
    result="FAIL"
    reason="${test_reason:-cargo_failed}"
    OVERALL_FAIL=1
  else
    reason="cargo_test_passed"
  fi
  qf_json_append_object "$JSON" \
    "name=cargo:$qf_filter" \
    "status=$result" \
    "result=$result" \
    "reason=$reason" \
    "target=$qf_target" \
    "feature_set=$qf_features" \
    "filter=$qf_filter" \
    "test_count=int:$test_count" \
    "command_status=int:$status" \
    "argv=json:$cmd_json" \
    "environment=json:$env_json" \
    "raw_output=$output_file"
  return 0
}

run_rg_check() {
  local name="$1"
  local output_file="$2"
  shift 2
  local -a rg_args=("$@")
  mkdir -p "$(dirname "$output_file")"
  : > "$output_file"
  local status=0
  if ! rg "${rg_args[@]}" >"$output_file" 2>&1; then
    status=$?
  fi
  cat "$output_file"
  local result="PASS"
  local reason="rg_matched"
  # For the three checks, expectations differ:
  # - absent checks should NOT be found -> rg exit 1 = PASS, 0 = FAIL
  # - present checks should be found -> rg exit 0 = PASS
  if [[ "$name" == *"absent"* ]]; then
    if [[ $status -eq 0 ]]; then
      result="FAIL"
      reason="unexpected_match_found"
      OVERALL_FAIL=1
    elif [[ $status -eq 1 ]]; then
      result="PASS"
      reason="no_match_as_expected"
      status=0
    else
      result="FAIL"
      reason="rg_error"
      OVERALL_FAIL=1
    fi
  else
    if [[ $status -eq 0 ]]; then
      result="PASS"
      reason="rg_matched"
    else
      result="FAIL"
      reason="rg_no_match"
      OVERALL_FAIL=1
    fi
  fi
  qf_json_append_object "$JSON" \
    "name=$name" \
    "status=$result" \
    "result=$result" \
    "reason=$reason" \
    "command_status=int:$status" \
    "argv=json:$(qf_json_array rg "${rg_args[@]}")" \
    "raw_output=$output_file"
}

run_modes_scope() {
  echo -e "\n> Testing FEC Zero Mode (no overhead at 0% loss)..."
  run_cargo_logged "$OUTPUT_DIR/modes-zero.log" "QUICFUSCATE_FEC_INITIAL_MODE=zero" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Light Mode..."
  run_cargo_logged "$OUTPUT_DIR/modes-light.log" "QUICFUSCATE_FEC_INITIAL_MODE=light" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Normal Mode..."
  run_cargo_logged "$OUTPUT_DIR/modes-normal.log" "QUICFUSCATE_FEC_INITIAL_MODE=normal" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Medium Mode..."
  run_cargo_logged "$OUTPUT_DIR/modes-medium.log" "QUICFUSCATE_FEC_INITIAL_MODE=medium" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Strong Mode..."
  run_cargo_logged "$OUTPUT_DIR/modes-strong.log" "QUICFUSCATE_FEC_INITIAL_MODE=strong" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Extreme Mode..."
  run_cargo_logged "$OUTPUT_DIR/modes-extreme.log" "QUICFUSCATE_FEC_INITIAL_MODE=extreme" -- test --release fec:: -- --nocapture
  echo -e "\n> Testing FEC Streaming Mode (Tetrys-like)..."
  run_cargo_logged "$OUTPUT_DIR/modes-streaming.log" "QUICFUSCATE_FEC_INITIAL_MODE=streaming" -- test --release fec:: -- --nocapture
}

run_gf16_scope() {
  echo -e "\n> Testing GF(2^16) SIMD Optimizations..."
  run_cargo_logged "$OUTPUT_DIR/gf16.log" "QUICFUSCATE_GF16_SIMD=1" "QUICFUSCATE_GF16_NIBBLE=1" -- test --release gf16 -- --nocapture
}

run_refactor_scope() {
  echo -e "\n=== FEC Refactor Validation (focused) ==="
  run_cargo_logged "$OUTPUT_DIR/refactor-stream_raw_roundtrip.log" -- test --release --lib stream_raw_roundtrip -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_batch_normal.log" -- test --release --lib test_batch_normal -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_batch_extreme_gf16.log" "QUICFUSCATE_FEC_INITIAL_MODE=extreme" -- test --release --lib test_batch_extreme_gf16 -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_streaming_tetrys.log" -- test --release --lib test_streaming_tetrys -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-gf16.log" "QUICFUSCATE_GF16_SIMD=1" -- test --release --lib gf16 -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_batch_extreme_gf16_coeff_len.log" -- test --release --lib test_batch_extreme_gf16_coeff_len -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_streaming_repairs_have_nonzero_coeffs.log" -- test --release --lib test_streaming_repairs_have_nonzero_coeffs -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_streaming_tetrys_burst_loss_recovery.log" -- test --release --lib test_streaming_tetrys_burst_loss_recovery -- --nocapture
  run_cargo_logged "$OUTPUT_DIR/refactor-test_streaming_emit_every_n.log" "QUICFUSCATE_FEC_STREAM_EVERY=3" -- test --release --lib test_streaming_emit_every_n -- --nocapture
  require_cmd rg
  # Structural checks: each emits separate record
  run_rg_check "rg:kalman_present" "$OUTPUT_DIR/rg-kalman.log" -n 'pub struct KalmanFilter' crates/qf-fec/src/kalman.rs
  run_rg_check "rg:mem_pool_present" "$OUTPUT_DIR/rg-mempool.log" -n "mem_pool: Arc<MemoryPool>" crates/qf-fec
  run_rg_check "rg:drop_fecpacket_present" "$OUTPUT_DIR/rg-drop.log" -n "impl Drop for FecPacket" crates/qf-fec
}

if should_run_scope modes; then
  run_modes_scope
fi
if should_run_scope gf16; then
  run_gf16_scope
fi
if should_run_scope refactor; then
  run_refactor_scope
fi

if [[ "$OVERALL_FAIL" -ne 0 ]]; then
  echo -e "\n[FAIL] FEC internal machine-room tests failed"
  json_end "$JSON"
  exit 1
fi

echo -e "\n[OK] FEC internal machine-room tests complete"
json_end "$JSON"
