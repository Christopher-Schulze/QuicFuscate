#!/usr/bin/env bash
# Description: Test suite runner: test-fec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
REFACTOR=0
REFACTOR_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --refactor) REFACTOR=1;;
    --refactor-only) REFACTOR=1; REFACTOR_ONLY=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "FEC Internal Machine-Room Test Suite"
      echo "  --refactor            Include refactor validation checks"
      echo "  --refactor-only       Only run refactor validation checks"
      usage_common_flags 2>/dev/null || true
      exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-fec-internal-${TIMESTAMP}"
validate_harness_inputs "$OUTPUT_DIR" "${CARGO_FEATURES:-}" "${RUSTFLAGS_EXTRA:-}" "${JOBS:-}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/fec-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fec_comprehensive"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  FEC Internal Machine-Room Test Suite"
echo "==============================================================="

run_cargo_logged() {
  local -a envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] || { error "run_cargo_logged requires -- before cargo arguments"; return 2; }
  shift
  run_cargo_with_env "${envs[@]}" -- "$@"
}

if [[ "$REFACTOR_ONLY" -eq 0 ]]; then
  # Internal machine-room coverage. These modes are not part of the public product contract.
  echo -e "\n> Testing FEC Zero Mode (no overhead at 0% loss)..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=zero" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Light Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=light" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Normal Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=normal" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Medium Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=medium" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Strong Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=strong" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Extreme Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=extreme" -- test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Streaming Mode (Tetrys-like)..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=streaming" -- test --release fec:: -- --nocapture

  # Test GF(2^16) SIMD paths
  echo -e "\n> Testing GF(2^16) SIMD Optimizations..."
  run_cargo_logged "QUICFUSCATE_GF16_SIMD=1" "QUICFUSCATE_GF16_NIBBLE=1" -- test --release gf16 -- --nocapture

fi

if [[ "$REFACTOR" -eq 1 ]]; then
  echo -e "\n=== FEC Refactor Validation (focused) ==="
  run_cargo_logged -- test --release --lib stream_raw_roundtrip -- --nocapture
  run_cargo_logged -- test --release --lib test_batch_normal -- --nocapture
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=extreme" -- test --release --lib test_batch_extreme_gf16 -- --nocapture
  run_cargo_logged -- test --release --lib test_streaming_tetrys -- --nocapture
  run_cargo_logged "QUICFUSCATE_GF16_SIMD=1" -- test --release --lib gf16 -- --nocapture
  run_cargo_logged -- test --release --lib test_batch_extreme_gf16_coeff_len -- --nocapture
  run_cargo_logged -- test --release --lib test_streaming_repairs_have_nonzero_coeffs -- --nocapture
  run_cargo_logged -- test --release --lib test_streaming_tetrys_burst_loss_recovery -- --nocapture
  run_cargo_logged "QUICFUSCATE_FEC_STREAM_EVERY=3" -- test --release --lib test_streaming_emit_every_n -- --nocapture

  require_cmd rg
  run bash -c "! rg -n 'struct KalmanFilter.*error_cov' src"
  run rg -n "pub mem_pool: Arc<MemoryPool>" src/fec/
  run rg -n "impl Drop for FecPacket" src/fec/
fi

echo -e "\n[OK] FEC internal machine-room tests complete"
json_end "$JSON"
