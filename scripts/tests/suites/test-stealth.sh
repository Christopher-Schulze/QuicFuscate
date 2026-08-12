#!/usr/bin/env bash
# Description: Test suite runner: test-stealth.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Stealth Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-stealth-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/stealth-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_stealth_comprehensive"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Stealth Comprehensive Test Suite"
echo "==============================================================="

if (( FAST )); then
  echo -e "\n> Fast mode enabled (focused stealth confidence set)"
  run env QUICFUSCATE_STEALTH_MODE=stealth cargo test --release --lib stealth:: -- --nocapture
  run_cargo test --release --lib qftls::tests::profile_from_ -- --nocapture
  run_cargo test --release \
    --test rt-stealth-config-toml \
    --test rt-stealth-persona-headers \
    -- --nocapture
  echo -e "\n[OK] Stealth Fast Tests Complete"
  json_end "$JSON"
  exit 0
fi

# Test all stealth modes
echo -e "\n> Testing Stealth Mode: Off..."
run env QUICFUSCATE_STEALTH_MODE=off cargo test --release --lib stealth:: -- --nocapture

echo -e "\n> Testing Stealth Mode: Normal..."
run env QUICFUSCATE_STEALTH_MODE=stealth cargo test --release --lib stealth:: -- --nocapture

echo -e "\n> Testing Stealth Mode: Maximum..."
run env QUICFUSCATE_STEALTH_MODE=anti_dpi cargo test --release --lib stealth:: -- --nocapture

# Test qftls profile mapping
echo -e "\n> Testing TLS Profile Mapping..."
run_cargo test --release --lib qftls::tests::profile_from_ -- --nocapture

# Test padding strategies
echo -e "\n> Testing Padding Strategies..."
run env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=0 cargo test --release --lib padding -- --nocapture
run env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=1 cargo test --release --lib padding -- --nocapture
run env QUICFUSCATE_STEALTH_PADDING=1 QUICFUSCATE_PADDING_STRATEGY=2 cargo test --release --lib padding -- --nocapture

# Test HTTP/3 MASQUE helpers
echo -e "\n> Testing HTTP/3 MASQUE Helpers..."
run_cargo test --release --lib transport::h3::connection::tests::masque -- --nocapture

# Integration fixtures (Rust tests)
echo -e "\n> Running Stealth Integration Fixtures..."
run_cargo test --release \
  --test rt-stealth-config-toml \
  --test rt-stealth-persona-headers \
  --test rt-stealth-ascii-count \
  -- --nocapture

echo -e "\n[OK] Stealth Comprehensive Tests Complete"
json_end "$JSON"
