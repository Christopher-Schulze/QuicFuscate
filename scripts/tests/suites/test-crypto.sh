#!/usr/bin/env bash
# Description: Test suite runner: test-crypto.
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
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Crypto & AEAD Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-crypto-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/crypto-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_crypto_comprehensive"; JSON_FIRST_RUN=1

run_qf_crypto_filter() {
  local pattern="$1"
  local list_output matched
  if ! list_output="$(QF_DISABLE_COMMAND_JSON_LOG=1 run_cargo test -p qf-crypto --release --lib "$pattern" -- --list 2>&1)"; then
    printf '%s\n' "$list_output" >&2
    return 1
  fi
  matched="$(printf '%s\n' "$list_output" | awk '/: test$/{count++} END{print count+0}')"
  if (( matched == 0 )); then
    die "No qf-crypto tests matched filter: ${pattern}"
  fi
  run_cargo test -p qf-crypto --release --lib "$pattern" -- --nocapture
}

run_qf_crypto_filter_with_env() {
  local env_assignment="$1"
  local pattern="$2"
  local list_output matched
  if ! list_output="$(QF_DISABLE_COMMAND_JSON_LOG=1 run_cargo_with_env "$env_assignment" -- test -p qf-crypto --release --lib "$pattern" -- --list 2>&1)"; then
    printf '%s\n' "$list_output" >&2
    return 1
  fi
  matched="$(printf '%s\n' "$list_output" | awk '/: test$/{count++} END{print count+0}')"
  if (( matched == 0 )); then
    die "No qf-crypto tests matched filter with ${env_assignment}: ${pattern}"
  fi
  run_cargo_with_env "$env_assignment" -- test -p qf-crypto --release --lib "$pattern" -- --nocapture
}

echo "==============================================================="
echo "  Crypto & AEAD Comprehensive Test Suite"
echo "==============================================================="

if (( FAST )); then
  echo -e "\n> Fast mode enabled (minimal crypto confidence set)"
  run_qf_crypto_filter aegis128l
  run_qf_crypto_filter morus
  run_qf_crypto_filter aes_gcm
  run_cargo test --release \
    --test rt-tls-cover-cipher \
    --test rt-ghash-sse-parity \
    -- --nocapture
  echo -e "\n[OK] Crypto Fast Tests Complete"
  json_end "$JSON"
  exit 0
fi

# Test AEGIS-128L
echo -e "\n> Testing AEGIS-128L..."
run_qf_crypto_filter aegis128l

# Test MORUS-1280-128
echo -e "\n> Testing MORUS-1280-128..."
run_qf_crypto_filter morus

# Test AES-GCM with hardware acceleration
echo -e "\n> Testing AES-GCM (Hardware Accelerated)..."
run_qf_crypto_filter aes_gcm

# Test GHASH PMULL (ARM)
echo -e "\n> Testing GHASH with PMULL (ARM)..."
run_qf_crypto_filter_with_env QUICFUSCATE_GHASH_PMULL=1 ghash

# Test ChaCha20-Poly1305 fallback
echo -e "\n> Testing ChaCha20-Poly1305..."
run_qf_crypto_filter chacha20poly1305

# Test AES header-protection key setup (key derivation path)
echo -e "\n> Testing AES Header-Protection Key Derivation..."
run_qf_crypto_filter aes_hp

# Test SIMD paths (x86_64)
echo -e "\n> Testing SIMD Paths (AVX2/SSE2)..."
run_qf_crypto_filter_with_env RUSTFLAGS=-C\ target-cpu=native simd

# Integration fixtures (Rust tests)
echo -e "\n> Running Crypto Integration Fixtures..."
run_cargo test --release \
  --test rt-baseline-oracles \
  --test rt-tls-cover-cipher \
  --test rt-ghash-sse-parity \
  --test rt-chacha-x4-parity \
  --test rt-chacha-x16-parity \
  --test rt-fake-hmac \
  -- --nocapture

echo -e "\n[OK] Crypto Comprehensive Tests Complete"
json_end "$JSON"
