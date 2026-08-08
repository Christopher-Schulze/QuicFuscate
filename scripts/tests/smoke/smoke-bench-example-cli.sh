#!/usr/bin/env bash
# Description: Negative CLI contract check for the benchmark and probe examples.
#
# These examples produce evidence, so two outcomes must be impossible: a panic on a
# typo, and a zero exit with no measurement. Every case below used to do one of them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${PROJECT_ROOT}"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR]"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/smoke/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

FAILURES=0
CASE_INDEX=0

# Assert that an invocation fails, without a panic and with a diagnostic.
expect_rejected() {
  local description="$1"; shift
  CASE_INDEX=$((CASE_INDEX + 1))
  local log="$OUTPUT_DIR/case-${CASE_INDEX}.log"
  if "$@" > "$log" 2>&1; then
    echo "[FAIL] ${description}: exited zero" >&2
    FAILURES=$((FAILURES + 1))
    return
  fi
  if grep -qi "panicked at" "$log"; then
    echo "[FAIL] ${description}: panicked instead of reporting a bounded error" >&2
    FAILURES=$((FAILURES + 1))
    return
  fi
  if ! grep -qiE "error|usage|unknown" "$log"; then
    echo "[FAIL] ${description}: rejected without a diagnostic" >&2
    FAILURES=$((FAILURES + 1))
    return
  fi
  echo "  ok: ${description}"
}

echo "> microbench"
expect_rejected "microbench rejects a malformed size" \
  cargo run --quiet --example microbench --features benches -- ghash notanumber 10
expect_rejected "microbench rejects zero iterations" \
  cargo run --quiet --example microbench --features benches -- ghash 1024 0
expect_rejected "microbench rejects an unknown benchmark" \
  cargo run --quiet --example microbench --features benches -- definitely-not-a-bench 1024 10

echo "> rng_bench"
expect_rejected "rng_bench rejects a malformed --total-mb" \
  cargo run --quiet --example rng_bench -- --total-mb notanumber
expect_rejected "rng_bench rejects an unknown option" \
  cargo run --quiet --example rng_bench -- --nope

echo "> shuffle_bench"
expect_rejected "shuffle_bench rejects a malformed length list" \
  cargo run --quiet --example shuffle_bench --features rust-tests -- --lengths 4,oops
expect_rejected "shuffle_bench rejects an all-unsupported length set" \
  cargo run --quiet --example shuffle_bench --features rust-tests -- --lengths 99

echo "> compress_bench"
expect_rejected "compress_bench rejects zero iterations" \
  cargo run --quiet --example compress_bench -- --iterations 0

echo "> fec_sim"
expect_rejected "fec_sim rejects an out-of-range loss" \
  cargo run --quiet --example fec_sim --features benches -- --loss 7.5
expect_rejected "fec_sim rejects an unknown option" \
  cargo run --quiet --example fec_sim --features benches -- --nope

echo "> crypto_backend_bench"
expect_rejected "crypto_backend_bench rejects an unknown backend" \
  cargo run --quiet --example crypto_backend_bench --features benches -- run nosuchbackend 1024 10
expect_rejected "crypto_backend_bench rejects zero iterations" \
  cargo run --quiet --example crypto_backend_bench --features benches -- run morus 1024 0

echo "> brain_probe"
expect_rejected "brain_probe rejects jitter without a unit" \
  cargo run --quiet --example brain_probe -- --jitter 5
expect_rejected "brain_probe rejects an unknown option" \
  cargo run --quiet --example brain_probe -- --nope

if (( FAILURES )); then
  echo "[FAIL] ${FAILURES} benchmark CLI contract case(s) failed" >&2
  exit 1
fi
echo "[OK] benchmark example CLI contract holds (${CASE_INDEX} cases)"
