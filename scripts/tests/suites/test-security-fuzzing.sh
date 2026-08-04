#!/usr/bin/env bash
# Description: Test suite runner: test-security-fuzzing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FUZZ_DURATION=60; FUZZ_JOBS=4
FUZZ_FORCE="${QUICFUSCATE_FORCE_FUZZ:-0}"
TOOLCHAIN_PIN="nightly"
if [[ -f "$PROJECT_ROOT/rust-toolchain.toml" ]]; then
  TOOLCHAIN_PIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$PROJECT_ROOT/rust-toolchain.toml" | head -n 1)
  if [[ -z "$TOOLCHAIN_PIN" ]]; then
    TOOLCHAIN_PIN="nightly"
  fi
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --duration) FUZZ_DURATION="$2"; shift;;
    --jobs) FUZZ_JOBS="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--duration SEC] [--jobs N]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "tests_security_fuzzing"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Security & Fuzzing Test Suite"
echo "==============================================================="

TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"
BASE_FEATURES="$(qf_cargo_test_feature_set "${CARGO_FEATURES:-rust-tests}")"
DISCOVERY_DONE=0; DISCOVERY_STATUS=""; DISCOVERY_REASON=""; DISCOVERY_COUNT=0
DISCOVERY_COMMAND_STATUS=""; DISCOVERY_COMMAND=""; DISCOVERY_ARGV_JSON="[]"; DISCOVERY_TARGET=""; DISCOVERY_FEATURES=""; ACTIVE_DISCOVERY_STATUS=""; ACTIVE_DISCOVERY_REASON=""
DISCOVERY_RAW_OUTPUT="$TEST_LIST_FILE"; DISCOVERY_STATUS_FOR_RUN="not_applicable"
COMMAND_ARGV_JSON="[]"; COMMAND_ENVIRONMENT_JSON="{}"

has_nightly_rustc() {
  if command -v rustup >/dev/null 2>&1; then
    if rustup toolchain list 2>/dev/null | grep -q "${TOOLCHAIN_PIN}"; then
      return 0
    fi
    if command -v rg >/dev/null 2>&1; then
      rustup run "${TOOLCHAIN_PIN}" rustc -Vv 2>/dev/null | rg -q 'nightly' && return 0
    else
      rustup run "${TOOLCHAIN_PIN}" rustc -Vv 2>/dev/null | grep -q 'nightly' && return 0
    fi
  fi
  if command -v rg >/dev/null 2>&1; then
    rustc -Vv 2>/dev/null | rg -q 'nightly'
    return $?
  fi
  rustc -Vv 2>/dev/null | grep -q 'nightly'
}

tsan_supported() {
  local os arch
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$os" == "Darwin" && "$arch" == "arm64" ]]; then
    return 1
  fi
  return 0
}

fuzz_enabled_on_host() {
  local os arch
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$os" == "Darwin" && "$arch" == "arm64" && "$FUZZ_FORCE" != "1" ]]; then
    return 1
  fi
  return 0
}

append_json() {
  local name="$1" status="$2" dur="$3"
  local result="PASS"
  case "$status" in
    fail) result="FAIL";;
    skipped) result="SKIP";;
  esac
  append_json_record "$name" "$status" "$dur" "$result" "legacy_case_without_structured_cargo_metadata" \
    "not_recorded" "not_recorded" "not_recorded" null null null "not_applicable" ""
}

append_json_record() {
  local name="$1" legacy_status="$2" dur="$3" result="$4" reason="$5"
  local target="$7" feature_set="$8" discovered_count="${9:-null}"
  local executed_count="${10:-null}" command_status="${11:-null}"
  local discovery_status="${12:-not_applicable}" raw_output="${13:-}"
  local environment_json="${COMMAND_ENVIRONMENT_JSON:-}"
  [[ -n "$environment_json" ]] || environment_json='{}'
  qf_json_append_object "$RESULTS_JSON" "name=$name" "status=$legacy_status" \
    "result=$result" "reason=$reason" "argv=json:${COMMAND_ARGV_JSON:-[]}" \
    "environment=json:$environment_json" "target=$target" \
    "feature_set=$feature_set" "discovered_test_count=json:$discovered_count" \
    "executed_test_count=json:$executed_count" "command_status=json:$command_status" \
    "discovery_status=$discovery_status" "raw_output=$raw_output" "duration_sec=int:$dur"
}

if [[ "${QUICFUSCATE_JSON_CONTRACT_TEST:-0}" == "1" ]]; then
  COMMAND_ARGV_JSON='["json-contract-fixture"]'
  COMMAND_ENVIRONMENT_JSON='{"fixture":"non-empty"}'
  append_json_record "json-contract-fixture" "ok" 0 "PASS" "structured_environment_contract" \
    "not_recorded" "fixture" "rust-tests" null null null "not_applicable" ""
  json_end "$RESULTS_JSON"
  exit 0
fi

record_platform_skip() {
  local name="$1" reason="$2" target="${3:-not_applicable}" feature_set="${4:-$BASE_FEATURES}"
  SKIPPED=$((SKIPPED+1))
  COMMAND_ARGV_JSON="[]"; COMMAND_ENVIRONMENT_JSON="{}"
  append_json_record "$name" "skipped" 0 "SKIP" "$reason" "not_applicable" "$target" "$feature_set" \
    null null null "SKIP" ""
}

ensure_test_list() {
  if [[ "$DISCOVERY_DONE" -eq 1 ]]; then
    ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
    ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_STATUS="$DISCOVERY_STATUS"; QF_CARGO_TEST_REASON="$DISCOVERY_REASON"
    QF_CARGO_TEST_COUNT="$DISCOVERY_COUNT"; QF_CARGO_TEST_COMMAND_STATUS="$DISCOVERY_COMMAND_STATUS"
    QF_CARGO_TEST_COMMAND="$DISCOVERY_COMMAND"; QF_CARGO_TEST_TARGET="$DISCOVERY_TARGET"
    QF_CARGO_TEST_ARGV_JSON="$DISCOVERY_ARGV_JSON"
    QF_CARGO_TEST_FEATURE_SET="$DISCOVERY_FEATURES"; QF_CARGO_TEST_FILTER="<all>"
    QF_CARGO_TEST_RAW_OUTPUT="$DISCOVERY_RAW_OUTPUT"
    return 0
  fi
  if qf_cargo_test_discover "$TEST_LIST_FILE" "lib" "$BASE_FEATURES" --release --features rust-tests --lib; then
    local legacy_status="ok"
  else
    local legacy_status="fail"
    FAILED=$((FAILED+1))
  fi
  DISCOVERY_DONE=1
  DISCOVERY_STATUS="$QF_CARGO_TEST_STATUS"
  DISCOVERY_REASON="$QF_CARGO_TEST_REASON"
  DISCOVERY_COUNT="$QF_CARGO_TEST_COUNT"
  DISCOVERY_COMMAND_STATUS="$QF_CARGO_TEST_COMMAND_STATUS"
  DISCOVERY_COMMAND="$QF_CARGO_TEST_COMMAND"
  DISCOVERY_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"
  DISCOVERY_TARGET="$QF_CARGO_TEST_TARGET"
  DISCOVERY_FEATURES="$QF_CARGO_TEST_FEATURE_SET"
  ACTIVE_DISCOVERY_STATUS="$DISCOVERY_STATUS"
  ACTIVE_DISCOVERY_REASON="$DISCOVERY_REASON"
  COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
  append_json_record "discovery:lib" "$legacy_status" 0 "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
    "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
    "$QF_CARGO_TEST_COMMAND_STATUS" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
}

test_pattern_exists() {
  local pattern="$1"
  ensure_test_list
  if [[ "$ACTIVE_DISCOVERY_STATUS" != "PASS" ]]; then
    return 2
  fi
  rg -F -q -- "$pattern" "$TEST_LIST_FILE"
}

run_optional_test() {
  local label="$1"; local pattern="$2"; shift 2
  local -a env_args=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    env_args+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_optional_test requires -- before cargo arguments"; return 2; }
  shift
  local -a cargo_args=("$@")
  if [[ "$#" -eq 0 ]]; then
    cargo_args=(--release --features rust-tests --lib "$pattern" -- --nocapture)
  fi
  if test_pattern_exists "$pattern"; then
    DISCOVERY_STATUS_FOR_RUN="$ACTIVE_DISCOVERY_STATUS"
    if [[ "${#env_args[@]}" -gt 0 ]]; then
      run_case "$label" "${env_args[@]}" -- cargo test "${cargo_args[@]}"
    else
      run_case "$label" -- cargo test "${cargo_args[@]}"
    fi
    DISCOVERY_STATUS_FOR_RUN="not_applicable"
    return 0
  fi
  local pattern_status=$?
  if [[ "$pattern_status" -eq 2 ]]; then
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
    append_json_record "$label" "fail" 0 "$ACTIVE_DISCOVERY_STATUS" "$ACTIVE_DISCOVERY_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
      "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  else
    SKIPPED=$((SKIPPED+1))
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"; COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
    append_json_record "$label" "skipped" 0 "SKIP" "pattern_not_found_after_target_scoped_discovery" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_COUNT" null \
      "$QF_CARGO_TEST_COMMAND_STATUS" "$ACTIVE_DISCOVERY_STATUS" "$QF_CARGO_TEST_RAW_OUTPUT"
  fi
  return 0
}

run_case() {
  local name="$1"; shift
  local envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  local cmd=("$@")
  local start=$(date +%s)
  TOTAL=$((TOTAL+1))
  echo -e "\n> [$TOTAL] $name"
  if [[ ${#envs[@]} -gt 0 ]]; then
    echo "  Env: ${envs[*]}"
  fi
  echo "  Cmd: ${cmd[*]}"
  if [[ "${cmd[0]:-}" == "cargo" && "${cmd[1]:-}" == "test" ]]; then
    local output_file="$OUTPUT_DIR/cargo-test-${TOTAL}.txt"
    local command_status=0
    if [[ ${#envs[@]} -gt 0 ]]; then
      if ( LOG_FILE="" JSON="" JSON_FILE="" run env "${envs[@]}" cargo "${cmd[@]:1}" ) > "$output_file" 2>&1; then
        command_status=0
      else
        command_status=$?
      fi
    elif LOG_FILE="" JSON="" JSON_FILE="" run_cargo "${cmd[@]:1}" > "$output_file" 2>&1; then
      command_status=0
    else
      command_status=$?
    fi
    cat "$output_file"
    qf_cargo_test_metadata_from_args "${cmd[@]:1}"
    if qf_cargo_test_classify_output run "$output_file" "$command_status" \
      "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" "$QF_CARGO_TEST_FILTER" "$QF_CARGO_TEST_COMMAND"; then
      :
    else
      :
    fi
    local duration=$(( $(date +%s) - start ))
    local legacy_status="ok"
    if [[ "$QF_CARGO_TEST_STATUS" != "PASS" ]]; then legacy_status="fail"; fi
    if [[ "$QF_CARGO_TEST_STATUS" == "PASS" ]]; then PASSED=$((PASSED+1)); else FAILED=$((FAILED+1)); fi
    COMMAND_ARGV_JSON="$QF_CARGO_TEST_ARGV_JSON"
    if [[ "${#envs[@]}" -gt 0 ]]; then
      COMMAND_ENVIRONMENT_JSON="$(qf_json_environment_with_assignments "${envs[@]}")"
    else
      COMMAND_ENVIRONMENT_JSON="$(qf_json_environment_with_assignments)"
    fi
    append_json_record "$name" "$legacy_status" "$duration" "$QF_CARGO_TEST_STATUS" "$QF_CARGO_TEST_REASON" \
      "$QF_CARGO_TEST_COMMAND" "$QF_CARGO_TEST_TARGET" "$QF_CARGO_TEST_FEATURE_SET" null \
      "$QF_CARGO_TEST_COUNT" "$QF_CARGO_TEST_COMMAND_STATUS" "$DISCOVERY_STATUS_FOR_RUN" "$QF_CARGO_TEST_RAW_OUTPUT"
    DISCOVERY_STATUS_FOR_RUN="not_applicable"
    return 0
  fi
  if [[ ${#envs[@]} -gt 0 ]]; then
    COMMAND_ARGV_JSON="$(qf_json_array env "${envs[@]}" "${cmd[@]}")"
    if [[ "${#envs[@]}" -gt 0 ]]; then
      COMMAND_ENVIRONMENT_JSON="$(qf_json_environment_with_assignments "${envs[@]}")"
    else
      COMMAND_ENVIRONMENT_JSON="$(qf_json_environment_with_assignments)"
    fi
  else
    COMMAND_ARGV_JSON="$(qf_json_array "${cmd[@]}")"
    COMMAND_ENVIRONMENT_JSON="$(qf_json_environment)"
  fi
  if [[ ${#envs[@]} -gt 0 ]]; then
    if [[ "${cmd[0]}" == "cargo" && "${cmd[1]:-}" != "fuzz" ]]; then
      if run env "${envs[@]}" cargo "${cmd[@]:1}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    else
      if run env "${envs[@]}" "${cmd[@]}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    fi
  else
    if [[ "${cmd[0]}" == "cargo" && "${cmd[1]:-}" != "fuzz" ]]; then
      if run_cargo "${cmd[@]:1}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    else
      if run "${cmd[@]}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    fi
  fi
  FAILED=$((FAILED+1))
  append_json "$name" "fail" $(( $(date +%s) - start ))
  return 0
}

run_named_test() {
  local label="$1"; shift
  local pattern="$1"; shift
  run_optional_test "$label" "$pattern" --
}

# Fuzzing configuration
FUZZ_DURATION=${FUZZ_DURATION:-60}  # seconds per target
FUZZ_JOBS=${FUZZ_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)}
FUZZ_ARTIFACT_ROOT="$OUTPUT_DIR/fuzz"
FUZZ_TARGET_DIR="${QUICFUSCATE_FUZZ_TARGET_DIR:-$SCRIPT_DIR/../../out/tests/_fuzz-target-cache}"
FUZZ_CORPUS_ROOT="$FUZZ_ARTIFACT_ROOT/corpus"
FUZZ_CRASH_ROOT="$FUZZ_ARTIFACT_ROOT/artifacts"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz"
FUZZ_SEED_ROOT="$FUZZ_DIR/seeds"
FUZZ_MANIFEST="$FUZZ_DIR/Cargo.toml"
validate_control_free_value "RUSTFLAGS_EXTRA" "${RUSTFLAGS_EXTRA:-}" 8192
validate_feature_list "CARGO_FEATURES" "${CARGO_FEATURES:-}"
validate_positive_int "fuzz duration" "$FUZZ_DURATION" 3600
validate_positive_int "fuzz jobs" "$FUZZ_JOBS" 64
validate_control_free_value "fuzz target directory" "$FUZZ_TARGET_DIR" 4096
if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi
mkdir -p "$FUZZ_TARGET_DIR" "$FUZZ_CORPUS_ROOT" "$FUZZ_CRASH_ROOT"

echo -e "\n> Configuration:"
echo "  Fuzz duration: ${FUZZ_DURATION}s per target"
echo "  Parallel jobs: ${FUZZ_JOBS}"
echo "  Host fuzz enabled: $(fuzz_enabled_on_host && echo yes || echo no)"
echo "  Fuzz seeds: ${FUZZ_SEED_ROOT}"
echo "  Runtime corpus: ${FUZZ_CORPUS_ROOT}"
echo "  Runtime crashes: ${FUZZ_CRASH_ROOT}"
echo "  Shared fuzz target dir: ${FUZZ_TARGET_DIR}"

# Build with fuzzing support
echo -e "\n> Building with fuzzing instrumentation..."
if command -v cargo-fuzz &> /dev/null && [[ -f "$FUZZ_MANIFEST" ]]; then
    if has_nightly_rustc && fuzz_enabled_on_host; then
      run_case "Fuzz build" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" CARGO_TARGET_DIR="$FUZZ_TARGET_DIR" -- cargo fuzz build --fuzz-dir "$FUZZ_DIR" || true
    elif has_nightly_rustc && ! fuzz_enabled_on_host; then
      warn "Skipping cargo-fuzz on macOS arm64 by default (set QUICFUSCATE_FORCE_FUZZ=1 to force)"
      record_platform_skip "Fuzz build" "host_fuzz_gate_requires_force_override" "cargo-fuzz" "$BASE_FEATURES"
    else
      warn "cargo-fuzz installed but nightly rustc is not active; skipping fuzz build"
      record_platform_skip "Fuzz build" "nightly_rustc_unavailable" "cargo-fuzz" "$BASE_FEATURES"
    fi
else
    if has_nightly_rustc; then
      echo "  cargo-fuzz not available; using nightly ASAN build"
      run_case "ASAN build" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" -- cargo build --release || true
    else
      warn "cargo-fuzz not available or fuzz manifest missing; skipping sanitizer build"
      record_platform_skip "Sanitizer build" "cargo_fuzz_or_fuzz_manifest_unavailable" "sanitizer" "$BASE_FEATURES"
    fi
fi

# Input validation tests
echo -e "\n=== Input Validation Tests ==="

echo -e "\n> Testing malformed packets..."
run_named_test "Malformed packets" "malformed_packet"

echo -e "\n> Testing oversized inputs..."
run_named_test "Oversized inputs" "oversized_input"

echo -e "\n> Testing boundary conditions..."
run_named_test "Boundary conditions" "boundary_conditions"

echo -e "\n> Testing integer overflows..."
run_optional_test "Integer overflow checks" "integer_overflow" "RUSTFLAGS=-Coverflow-checks=on" --

# Memory safety tests
echo -e "\n=== Memory Safety Tests ==="

echo -e "\n> Testing buffer overflows..."
run_named_test "Buffer overflow" "buffer_overflow"

echo -e "\n> Testing use-after-free..."
run_named_test "Use-after-free" "use_after_free"

echo -e "\n> Testing double-free..."
run_named_test "Double-free" "double_free"

# Concurrency tests
echo -e "\n=== Concurrency Safety Tests ==="

echo -e "\n> Testing data races..."
if has_nightly_rustc && tsan_supported; then
  run_optional_test "Data races (TSAN)" "data_race" \
    "RUSTUP_TOOLCHAIN=${TOOLCHAIN_PIN}" \
    "RUSTFLAGS=-Zsanitizer=thread -Cunsafe-allow-abi-mismatch=sanitizer" --
else
  run_optional_test "Data races" "data_race" --
fi

echo -e "\n> Testing deadlocks..."
run_optional_test "Deadlock detection" "deadlock_detection" -- \
  --release --features rust-tests --lib deadlock_detection -- --nocapture --test-threads=8

echo -e "\n> Testing race conditions..."
run_optional_test "Race conditions" "race_conditions" -- \
  --release --features rust-tests --lib race_conditions -- --nocapture --test-threads=16

# Crypto security tests
echo -e "\n=== Cryptographic Security Tests ==="

echo -e "\n> Testing timing attacks resistance..."
run_named_test "Timing attack resistance" "timing_attack"

echo -e "\n> Testing key material handling..."
run_named_test "Key material handling" "key_material"

echo -e "\n> Testing PRNG quality..."
run_named_test "PRNG quality" "prng_quality"

# Protocol security tests
echo -e "\n=== Protocol Security Tests ==="

echo -e "\n> Testing replay attacks..."
run_named_test "Replay attacks" "replay_attack"

echo -e "\n> Testing amplification attacks..."
run_named_test "Amplification attacks" "amplification_attack"

echo -e "\n> Testing resource exhaustion..."
run_named_test "Resource exhaustion" "resource_exhaustion"

echo -e "\n> Testing active probe detection invariants..."
run_case "Active probe detection invariants" -- cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture

# Fuzzing targets
if command -v cargo-fuzz &> /dev/null && [[ -f "$FUZZ_MANIFEST" ]] && has_nightly_rustc && fuzz_enabled_on_host; then
    echo -e "\n=== Fuzzing Tests ==="
    
    FUZZ_TARGETS=(
        "packet_parsing"
        "frame_decoding"
        "crypto_operations"
        "fec_encoding"
        "varint_parsing"
        "connection_handling"
    )
    
    for target in "${FUZZ_TARGETS[@]}"; do
        runtime_corpus="$FUZZ_CORPUS_ROOT/${target}"
        runtime_crash="$FUZZ_CRASH_ROOT/${target}"
        seed_corpus="$FUZZ_SEED_ROOT/${target}"
        mkdir -p "$runtime_corpus" "$runtime_crash"
        if [[ -d "$seed_corpus" ]]; then
          cp -a "$seed_corpus/." "$runtime_corpus/" 2>/dev/null || true
        fi
        run_case "Fuzz ${target}" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" CARGO_TARGET_DIR="$FUZZ_TARGET_DIR" -- cargo fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -jobs=${FUZZ_JOBS} -max_total_time=${FUZZ_DURATION} -max_len=65536 -timeout=10 -artifact_prefix="$runtime_crash/" "$runtime_corpus"
    done
else
    warn "Fuzz targets skipped (cargo-fuzz missing, fuzz manifest missing, nightly rustc not active, or host gating active)"
    record_platform_skip "Fuzz targets" "cargo_fuzz_manifest_nightly_or_host_prerequisite_unavailable" "cargo-fuzz" "$BASE_FEATURES"
fi

# Property-based testing
echo -e "\n=== Property-Based Tests ==="

echo -e "\n> Running dedicated property suite..."
run_case "Property suite (proptest)" -- cargo test --release --features rust-tests --test rt-property-suite -- --nocapture

echo -e "\n> Testing FEC properties..."
run_named_test "FEC properties" "fec_properties"

echo -e "\n> Testing crypto properties..."
run_named_test "Crypto properties" "crypto_properties"

echo -e "\n> Testing transport invariants..."
run_named_test "Transport invariants" "transport_invariants"

# Sanitizer tests
echo -e "\n=== Sanitizer Tests ==="

if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    if has_nightly_rustc; then
      SYSROOT=$(rustc +"${TOOLCHAIN_PIN}" --print sysroot)
      HOST_TRIPLE=$(rustc +"${TOOLCHAIN_PIN}" -vV | sed -n 's/^host: //p')
      ASAN_RT="${SYSROOT}/lib/rustlib/${HOST_TRIPLE}/lib/librustc-nightly_rt.asan.dylib"
      UBSAN_RT="${SYSROOT}/lib/rustlib/${HOST_TRIPLE}/lib/librustc-nightly_rt.ubsan.dylib"

      echo -e "\n> Running with AddressSanitizer..."
      if [[ "$OSTYPE" == "darwin"* && "$(uname -m 2>/dev/null || true)" == "arm64" ]]; then
        warn "ASAN full test is unstable on macOS arm64 in this toolchain setup; skipping"
        record_platform_skip "ASAN full test" "macos_arm64_toolchain_instability" "asan" "$BASE_FEATURES"
      elif [[ "$OSTYPE" == "darwin"* && -f "$ASAN_RT" ]]; then
        run_case "ASAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" DYLD_INSERT_LIBRARIES="${ASAN_RT}" DYLD_FORCE_FLAT_NAMESPACE=1 -- cargo test --release --features rust-tests || true
      else
        run_case "ASAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" -- cargo test --release --features rust-tests || true
      fi

      echo -e "\n> Running with MemorySanitizer..."
      if [[ "$OSTYPE" == "darwin"* ]]; then
        warn "MSAN is not supported on macOS; skipping"
        record_platform_skip "MSAN full test" "platform_unsupported_macos" "msan" "$BASE_FEATURES"
      else
        run_case "MSAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=memory" -- cargo test --release --features rust-tests || true
      fi

      echo -e "\n> Running with UndefinedBehaviorSanitizer..."
      if [[ "$OSTYPE" == "darwin"* && ! -f "$UBSAN_RT" ]]; then
        warn "UBSAN runtime not available for this toolchain; skipping"
        record_platform_skip "UBSAN full test" "nightly_ubsan_runtime_unavailable" "ubsan" "$BASE_FEATURES"
      else
        run_case "UBSAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=undefined" -- cargo test --release --features rust-tests || true
      fi
    else
      warn "Sanitizers require nightly rustc; skipping"
      record_platform_skip "ASAN full test" "nightly_rustc_unavailable" "asan" "$BASE_FEATURES"
      record_platform_skip "MSAN full test" "nightly_rustc_unavailable" "msan" "$BASE_FEATURES"
      record_platform_skip "UBSAN full test" "nightly_rustc_unavailable" "ubsan" "$BASE_FEATURES"
    fi
fi

echo -e "\n==============================================================="
echo "  Security & Fuzzing Summary"
echo "==============================================================="
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
json_end "$RESULTS_JSON"
if [[ "$FAILED" -gt 0 ]]; then
  echo -e "\n[FAIL] Security & Fuzzing Tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Security & Fuzzing Tests Complete"
