#!/usr/bin/env bash
# Description: Test suite runner: test-crypto.
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
    --help|-h) echo "Usage: $(basename "$0") [--only aegis,morus,aes-gcm,ghash,chacha,aes-hp,simd,integration] [options]"; echo "Crypto & AEAD Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

validate_scope_selection() {
  qf_validate_scope_selection "$ONLY" "aegis,morus,aes-gcm,ghash,chacha,aes-hp,simd,integration"
}

scope_selected() {
  qf_scope_selected "$ONLY" "$1"
}

validate_scope_selection

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-crypto-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/crypto-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_crypto_comprehensive"; JSON_FIRST_RUN=1

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

for scope in aegis morus aes-gcm ghash chacha aes-hp simd integration; do
  if ! scope_selected "$scope"; then
    record_scope_skip "$scope"
  fi
done

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
  if scope_selected aegis; then
    run_qf_crypto_filter aegis128l
  fi
  if scope_selected morus; then
    run_qf_crypto_filter morus
  fi
  if scope_selected aes-gcm; then
    run_qf_crypto_filter aes_gcm
  fi
  if [[ "$ONLY" != "all" ]] && scope_selected ghash; then
    run_qf_crypto_filter_with_env QUICFUSCATE_GHASH_PMULL=1 ghash
  fi
  if scope_selected integration; then
    run_cargo test --release \
      --test rt-tls-cover-cipher \
      --test rt-ghash-sse-parity \
      -- --nocapture
  fi
  echo -e "\n[OK] Crypto Fast Tests Complete"
  json_end "$JSON"
  exit 0
fi

# Test AEGIS-128L
if scope_selected aegis; then
  echo -e "\n> Testing AEGIS-128L..."
  run_qf_crypto_filter aegis128l
fi

# Test MORUS-1280-128
if scope_selected morus; then
  echo -e "\n> Testing MORUS-1280-128..."
  run_qf_crypto_filter morus
fi

# Test AES-GCM with hardware acceleration
if scope_selected aes-gcm; then
  echo -e "\n> Testing AES-GCM (Hardware Accelerated)..."
  run_qf_crypto_filter aes_gcm
fi

# Test GHASH PMULL (ARM)
if scope_selected ghash; then
  echo -e "\n> Testing GHASH with PMULL (ARM)..."
  run_qf_crypto_filter_with_env QUICFUSCATE_GHASH_PMULL=1 ghash
fi

# Test ChaCha20-Poly1305 fallback
if scope_selected chacha; then
  echo -e "\n> Testing ChaCha20-Poly1305..."
  run_qf_crypto_filter chacha20poly1305
fi

# Test AES header-protection key setup (key derivation path)
if scope_selected aes-hp; then
  echo -e "\n> Testing AES Header-Protection Key Derivation..."
  run_qf_crypto_filter aes_hp
fi

# Test SIMD paths (x86_64)
if scope_selected simd; then
  echo -e "\n> Testing SIMD Paths (AVX2/SSE2)..."
  run_qf_crypto_filter_with_env RUSTFLAGS=-C\ target-cpu=native simd
fi

# Integration fixtures (Rust tests)
if scope_selected integration; then
  echo -e "\n> Running Crypto Integration Fixtures..."
  run_cargo test --release \
    --test rt-baseline-oracles \
    --test rt-tls-cover-cipher \
    --test rt-ghash-sse-parity \
    --test rt-chacha-x4-parity \
    --test rt-chacha-x16-parity \
    --test rt-fake-hmac \
    -- --nocapture
fi

echo -e "\n[OK] Crypto Comprehensive Tests Complete"
json_end "$JSON"
