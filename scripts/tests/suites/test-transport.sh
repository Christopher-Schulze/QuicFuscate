#!/usr/bin/env bash
# Description: Test suite runner: test-transport.
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
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Transport Layer Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-transport-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/transport-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_transport_comprehensive"; JSON_FIRST_RUN=1
URING_PROOF_FAILURE=0
URING_PROOF_TIMEOUT_SECONDS=900

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

run_verified_target() {
  local target="$1"
  local expected_test_name="$2"
  local feature_set="$3"
  local output_file="$OUTPUT_DIR/${target}.log"
  if qf_cargo_test_run_expect \
    "$output_file" "test:${target}" "$feature_set" "$expected_test_name" \
    "$expected_test_name" --release --test "$target" -- --nocapture; then
    qf_json_append_object "$JSON" \
      "name=$target" \
      "status=PASS" \
      "result=PASS" \
      "reason=expected_test_executed" \
      "target=test:${target}" \
      "feature_set=$(qf_cargo_test_feature_set "$feature_set")" \
      "test_count=int:$QF_CARGO_TEST_COUNT" \
      "command_status=int:0" \
      "raw_output=$output_file"
    return 0
  fi
  local command_status="$?"
  qf_json_append_object "$JSON" \
    "name=$target" \
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

write_uring_proof_evidence() {
  local name="$1"
  local status="$2"
  local reason="$3"
  local log_file="$4"
  local command_status="$5"
  local environment_json="$6"
  local command_argv_json="$7"
  local command_line="$8"
  qf_json_write_object_file "$OUTPUT_DIR/${name}.json" \
    "schema=quicfuscate.io_uring_proof.v1" \
    "name=$name" \
    "status=$status" \
    "reason=$reason" \
    "log=$log_file" \
    "command_status=int:$command_status" \
    "source_revision=$(git rev-parse HEAD)" \
    "environment=json:$environment_json" \
    "argv=json:$command_argv_json" \
    "command=$command_line"
  qf_json_append_object "$JSON" \
    "name=$name" \
    "status=$status" \
    "result=$status" \
    "reason=$reason" \
    "command_status=int:$command_status" \
    "source_revision=$(git rev-parse HEAD)" \
    "environment=json:$environment_json" \
    "argv=json:$command_argv_json" \
    "raw_output=$log_file"
}

run_bounded_cargo() {
  local timeout_seconds="$1"
  shift
  local -a env_assignments=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    env_assignments+=("$1")
    shift
  done
  if [[ "${1:-}" != "--" ]]; then
    error "run_bounded_cargo requires -- before cargo arguments"
    return 2
  fi
  shift

  local -a cargo_environment=()
  [[ -n "${RUSTFLAGS_EXTRA:-}" ]] && cargo_environment+=("RUSTFLAGS=$RUSTFLAGS_EXTRA")
  [[ -n "${CARGO_TARGET_DIR:-}" ]] && cargo_environment+=("CARGO_TARGET_DIR=$CARGO_TARGET_DIR")
  timeout --signal=TERM "${timeout_seconds}s" \
    env "${env_assignments[@]}" "${cargo_environment[@]}" cargo "$@"
}

run_required_uring_proof() {
  local name="$1"
  local marker="$2"
  local environment_json="$3"
  shift 3
  local log_file="$OUTPUT_DIR/${name}.log"
  local command_argv_json
  command_argv_json="$(qf_json_array "$@")"
  local command_line
  command_line="$(printf '%q ' "$@")"
  command_line="${command_line% }"
  local command_status=0
  if "$@" >"$log_file" 2>&1; then
    command_status=0
  else
    command_status=$?
  fi
  cat "$log_file"

  local status reason
  if [[ "$command_status" -eq 0 ]] && grep -Fq "${marker}=SUPPORTED" "$log_file"; then
    status="PASS"
    reason="kernel_executed"
  elif grep -Fq "${marker}=UNAVAILABLE" "$log_file"; then
    status="UNAVAILABLE"
    reason="kernel_capability_unavailable"
  else
    status="FAIL"
    reason="command_failed_or_missing_status_marker"
  fi

  write_uring_proof_evidence \
    "$name" "$status" "$reason" "$log_file" "$command_status" "$environment_json" \
    "$command_argv_json" "$command_line"
  if [[ "$status" != "PASS" ]]; then
    URING_PROOF_FAILURE=1
    return 1
  fi
}

echo "==============================================================="
echo "  Transport Layer Comprehensive Test Suite (validated migration contract)"
echo "==============================================================="

echo -e "\n> Testing Basic Transport (unit tests)..."
run_cargo test --release --lib transport:: -- --nocapture

# Test io_uring fast path (Linux)
echo -e "\n> Testing io_uring UDP Fast Path..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    QUICFUSCATE_FASTPATH=auto \
    run_verified_target rt-transport-uring uring_batch_sender_initialises io_uring,rust-tests
else
    record_platform_skip "rt-transport-uring" "host_os_not_linux" "test:rt-transport-uring" "io_uring,rust-tests"
fi

echo -e "\n> Testing io_uring zero-length receive rearm proof..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    rearm_environment="$(qf_json_environment_with_assignments "QUICFUSCATE_FASTPATH=auto")"
    if ! run_required_uring_proof \
      "uring-rearm" "QF_IO_URING_REARM_STATUS" "$rearm_environment" \
      run_bounded_cargo "$URING_PROOF_TIMEOUT_SECONDS" QUICFUSCATE_FASTPATH=auto -- \
      test --release --features io_uring,rust-tests --lib \
      optimize::uring_batch::tests::recv_rearms_after_zero_length_datagrams -- \
      --nocapture --exact; then
        echo "[FAIL] io_uring zero-length receive rearm proof did not pass" >&2
    fi
else
    record_platform_skip "uring-rearm" "host_os_not_linux" "lib" "io_uring,rust-tests"
fi

echo -e "\n> Testing opt-in io_uring SendMsgZc completion proof..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    zc_environment="$(qf_json_environment_with_assignments \
      "QUICFUSCATE_FASTPATH=auto" "QUICFUSCATE_IO_URING_ZC=1")"
    if ! run_required_uring_proof \
      "uring-zc" "QF_IO_URING_ZC_STATUS" "$zc_environment" \
      run_bounded_cargo "$URING_PROOF_TIMEOUT_SECONDS" QUICFUSCATE_FASTPATH=auto QUICFUSCATE_IO_URING_ZC=1 -- \
      test --release --features io_uring,rust-tests --test rt-transport-uring \
      uring_zc_opt_in_loopback_and_error_contract -- \
      --nocapture --exact --test-threads=1; then
        echo "[FAIL] opt-in io_uring SendMsgZc proof did not pass" >&2
    fi
else
    record_platform_skip "uring-zc" "host_os_not_linux" "test:rt-transport-uring" "io_uring,rust-tests"
fi

echo -e "\n> Testing Linux Kernel Hotpath Smoke..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    QUICFUSCATE_FASTPATH=auto \
    run_verified_target \
      rt-io-hotpath-kernel-integration \
      zc_batch_sendmmsg_kernel_path_sends_all_datagrams \
      io_uring,rust-tests
else
    record_platform_skip \
      "rt-io-hotpath-kernel-integration" "host_os_not_linux" \
      "test:rt-io-hotpath-kernel-integration" "io_uring,rust-tests"
fi

echo -e "\n> Testing Anti-Replay Strike Register..."
run_cargo test --features rust-tests --test rt-anti-replay -- --nocapture

echo -e "\n> Testing Congestion Control Algorithms..."
run_cargo test --features rust-tests --test rt-cc-algorithms -- --nocapture

echo -e "\n> Testing Transport Integration Targets..."
run_verified_target rt-transport-connection connection_datagram_queues_and_thresholds rust-tests
run_verified_target rt-transport-config config_accepts_known_version rust-tests
run_verified_target rt-transport-batch-processor batch_processor_init_acceleration_is_ok rust-tests
run_verified_target rt-transport-frames-roundtrip roundtrip_basic_frames rust-tests
run_verified_target rt-transport-packet-headers short_header_roundtrip rust-tests
run_verified_target rt-transport-recovery recovery_counters_and_pto_progression rust-tests
run_verified_target rt-transport-udpfast aligned_buffer_is_cacheline_aligned rust-tests
run_verified_target rt-transport-h3 h3_send_request_returns_stream_id rust-tests
run_verified_target rt-pnspace-ack-policy ack_elicitation_threshold_and_ranges rust-tests
run_verified_target rt-udp-batch-send udpfast_send_batch_sends_all_packets rust-tests
run_verified_target rt-harness-udpfast harness_udpfast_loopback_smoke rust-tests

json_end "$JSON"
if [[ "$URING_PROOF_FAILURE" -ne 0 ]]; then
    echo "[FAIL] Required Linux io_uring evidence was unavailable or failed" >&2
    exit 1
fi
echo -e "\n[OK] Transport Comprehensive Tests Complete"
