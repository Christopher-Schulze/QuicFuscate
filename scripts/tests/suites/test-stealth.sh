#!/usr/bin/env bash
# Description: Test suite runner: test-stealth.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
ONLY="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --only) ONLY="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--only modes,qftls,padding,masque,integration] [options]"; echo "Stealth Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

validate_scope_selection() {
  qf_validate_scope_selection "$ONLY" "modes,qftls,padding,masque,integration"
}

scope_selected() {
  qf_scope_selected "$ONLY" "$1"
}

fast_scope_selected() {
  case "$1" in
    modes|qftls|integration) return 0;;
    *) return 1;;
  esac
}

validate_scope_selection

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-stealth-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/stealth-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_stealth_comprehensive"; JSON_FIRST_RUN=1

qf_json_append_object "$JSON" \
  "name=selection" \
  "status=PASS" \
  "result=PASS" \
  "reason=explicit_scope_selection" \
  "selected_scopes=$ONLY" \
  "mode=$( (( FAST )) && printf 'fast' || printf 'full' )" \
  "command_status=int:0" \
  "raw_output="

record_scope_skip() {
  local scope="$1"
  local reason="not_selected_by_scope"
  if (( FAST )) && [[ "$ONLY" == "all" ]]; then
    reason="fast_profile_omits_scope"
  fi
  qf_json_append_object "$JSON" \
    "name=scope-$scope" \
    "status=SKIP" \
    "result=SKIP" \
    "reason=$reason" \
    "command_status=int:0" \
    "raw_output="
}

for scope in modes qftls padding masque integration; do
  if ! scope_selected "$scope" || { (( FAST )) && [[ "$ONLY" == "all" ]] && ! fast_scope_selected "$scope"; }; then
    record_scope_skip "$scope"
  fi
done

run_qftls_profile_tests() {
  local pattern="qftls::tests::test_profile_"
  local list_output matched
  if ! list_output="$(QF_DISABLE_COMMAND_JSON_LOG=1 run_cargo test --release --lib "$pattern" -- --list 2>&1)"; then
    printf '%s\n' "$list_output" >&2
    return 1
  fi
  matched="$(printf '%s\n' "$list_output" | awk '/: test$/{count++} END{print count+0}')"
  if (( matched == 0 )); then
    die "No QFTLS profile tests matched filter: ${pattern}"
  fi
  run_cargo test --release --lib "$pattern" -- --nocapture
}

echo "==============================================================="
echo "  Stealth Comprehensive Test Suite"
echo "==============================================================="

if (( FAST )); then
  echo -e "\n> Fast mode enabled (focused stealth confidence set)"
  if scope_selected modes; then
    run_cargo_with_env QUICFUSCATE_STEALTH_MODE=stealth -- test --release --lib stealth:: -- --nocapture
  fi
  if scope_selected qftls; then
    run_qftls_profile_tests
  fi
  if [[ "$ONLY" != "all" ]] && scope_selected padding; then
    run_cargo_with_env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=0 -- test --release --lib padding -- --nocapture
  fi
  if [[ "$ONLY" != "all" ]] && scope_selected masque; then
    run_cargo test --release --lib transport::h3::connection::tests::masque -- --nocapture
  fi
  if scope_selected integration; then
    run_cargo test --release \
      --test rt-stealth-config-toml \
      --test rt-stealth-persona-headers \
      -- --nocapture
  fi
  echo -e "\n[OK] Stealth Fast Tests Complete"
  json_end "$JSON"
  exit 0
fi

# Test all stealth modes
if scope_selected modes; then
  echo -e "\n> Testing Stealth Mode: Off..."
  run_cargo_with_env QUICFUSCATE_STEALTH_MODE=off -- test --release --lib stealth:: -- --nocapture

  echo -e "\n> Testing Stealth Mode: Normal..."
  run_cargo_with_env QUICFUSCATE_STEALTH_MODE=stealth -- test --release --lib stealth:: -- --nocapture

  echo -e "\n> Testing Stealth Mode: Maximum..."
  run_cargo_with_env QUICFUSCATE_STEALTH_MODE=anti_dpi -- test --release --lib stealth:: -- --nocapture
fi

# Test qftls profile mapping
if scope_selected qftls; then
  echo -e "\n> Testing TLS Profile Mapping..."
  run_qftls_profile_tests
fi

# Test padding strategies
if scope_selected padding; then
  echo -e "\n> Testing Padding Strategies..."
  run_cargo_with_env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=0 -- test --release --lib padding -- --nocapture
  run_cargo_with_env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=1 -- test --release --lib padding -- --nocapture
  run_cargo_with_env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=2 -- test --release --lib padding -- --nocapture
fi

# Test HTTP/3 MASQUE helpers
if scope_selected masque; then
  echo -e "\n> Testing HTTP/3 MASQUE Helpers..."
  run_cargo test --release --lib transport::h3::connection::tests::masque -- --nocapture
fi

# Integration fixtures (Rust tests)
if scope_selected integration; then
  echo -e "\n> Running Stealth Integration Fixtures..."
  run_cargo test --release \
    --test rt-stealth-config-toml \
    --test rt-stealth-persona-headers \
    --test rt-stealth-ascii-count \
    -- --nocapture
fi

echo -e "\n[OK] Stealth Comprehensive Tests Complete"
json_end "$JSON"
