#!/usr/bin/env bash
# Description: Build helper: build-check.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; SKIP_CLIPPY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --skip-clippy) SKIP_CLIPPY=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--skip-clippy]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/build/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "build_check"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  QuicFuscate Build Check"
echo "==============================================================="

# This runner is consumed as a gate, so a failed required check must reach the exit
# status. It previously downgraded fmt, Clippy, and benchmark failures to warnings and
# then printed a success line, which made a green result unusable as evidence.
FAILED_CHECKS=()
SKIPPED_CHECKS=()

record_check() {
  local name="$1" result="$2" reason="$3" status="$4"
  qf_json_append_object "$JSON" "check=$name" "result=$result" "reason=$reason" \
    "command_status=json:$status" "environment=json:$(qf_json_environment)"
  case "$result" in
    FAIL) FAILED_CHECKS+=("$name");;
    SKIP) SKIPPED_CHECKS+=("$name");;
  esac
}

# Run one required check and record its exact status.
run_check() {
  local name="$1"; shift
  echo -e "\n> ${name}..."
  local status=0
  "$@" || status=$?
  if (( status == 0 )); then
    record_check "$name" PASS "" "$status"
  else
    record_check "$name" FAIL "command_failed" "$status"
    echo "[FAIL] ${name} exited with status ${status}" >&2
  fi
}

run_check "formatting" cargo fmt --check

if [[ "$SKIP_CLIPPY" -eq 1 ]]; then
  # An explicit skip is recorded and surfaced in the final line. It must never be
  # presented as a full quality pass.
  echo -e "\n> clippy: skipped by --skip-clippy"
  record_check "clippy" SKIP "explicit_skip_clippy" "null"
else
  run_check "clippy" cargo clippy --all-targets -- -D warnings
fi

run_check "compilation" cargo check

if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_FULL_TEST_COMPILE_GIB:-10}" "full test binary compilation" "$PROJECT_ROOT"; then
  run_check "test-compilation" run_cargo test --no-run --features rust-tests
else
  record_check "test-compilation" SKIP "low_disk" "null"
fi

if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_BENCH_COMPILE_GIB:-10}" "benchmark binary compilation" "$PROJECT_ROOT"; then
  run_check "benchmark-compilation" cargo bench --no-run --features benches
else
  record_check "benchmark-compilation" SKIP "low_disk" "null"
fi

# Snapshot the lists before recording, so the aggregate record does not add itself to
# the failure list it is reporting.
FAILED_LIST="${FAILED_CHECKS[*]:-none}"
SKIPPED_LIST="${SKIPPED_CHECKS[*]:-none}"
FAILED_COUNT=${#FAILED_CHECKS[@]}
AGGREGATE="PASS"
(( FAILED_COUNT )) && AGGREGATE="FAIL"
qf_json_append_object "$JSON" "check=aggregate" "result=$AGGREGATE" \
  "reason=failed=${FAILED_LIST} skipped=${SKIPPED_LIST}" \
  "command_status=json:${FAILED_COUNT}" "environment=json:$(qf_json_environment)"
json_end "$JSON"

if (( FAILED_COUNT )); then
  echo -e "\n[FAIL] Build check failed: ${FAILED_LIST}" >&2
  exit 1
fi
if [[ "$SKIPPED_LIST" != "none" ]]; then
  echo -e "\n[OK] Build check passed with skipped checks: ${SKIPPED_LIST}"
else
  echo -e "\n[OK] Build check passed"
fi
