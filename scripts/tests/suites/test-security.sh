#!/usr/bin/env bash
# Description: Test suite runner: test-security.
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
      echo "Usage: $(basename "$0") [--only security,property] [options]"; echo "Security Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

validate_scope_selection() {
  qf_validate_scope_selection "$ONLY" "security,property"
}

scope_selected() {
  qf_scope_selected "$ONLY" "$1"
}

validate_scope_selection

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-security-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/security-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_security"; JSON_FIRST_RUN=1

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

for scope in security property; do
  if ! scope_selected "$scope"; then
    record_scope_skip "$scope"
  fi
done

exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi

echo "==============================================================="
echo "  Security Test Suite"
echo "==============================================================="

if scope_selected security; then
  echo -e "\n> Running Security Suite..."
  run_cargo test --release \
    --test rt-security-suite \
    -- --nocapture
fi

if scope_selected property; then
  echo -e "\n> Running Property Suite..."
  run_cargo test --release \
    --test rt-property-suite \
    -- --nocapture
fi

echo -e "\n[OK] Security Tests Complete"
json_end "$JSON"
