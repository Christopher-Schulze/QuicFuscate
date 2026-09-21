#!/usr/bin/env bash
# Description: Shell utility script: smoke-avx10.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; REQUIRE=0; BENCH_BYTES="64MiB"; BENCH_ITERS=50; RUSTFLAGS_EXTRA="-C target-cpu=native"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --require) REQUIRE=1;;
    --bench-bytes) BENCH_BYTES="$2"; shift;;
    --bench-iters) BENCH_ITERS="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --help|-h)
      cat <<'USAGE'
Usage: smoke-avx10.sh [options]

Options:
  --output-dir DIR   Store logs under DIR (default: scripts/out/tests/...)
  --require          Fail if AVX10.1 is not detected (for CI gating)
  --bench-bytes SZ   Payload per iteration for benches (default: 64MiB)
  --bench-iters N    Iterations per bench run (default: 50)
  --rustflags STR    Extra RUSTFLAGS to apply (default: -C target-cpu=native)
  --help             Show this help

The script detects AVX10.1 capabilities via `cargo run --release --example microbench -- profile`,
runs SIMD self-checks when available, and captures baseline microbench metrics for future regression
comparisons. On non-x86_64 or hosts without AVX10.1 it exits successfully unless `--require` is set.
USAGE
      exit 0;;
    *) break;;
  esac
  shift
done

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
  echo "[avx10-smoke] skipping: host arch '$ARCH' does not support x86_64 AVX10." >&2
  [[ "$REQUIRE" -eq 1 ]] && exit 1 || exit 0
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee "$LOG_FILE") 2>&1

if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi

echo "==============================================================="
echo "  AVX10.1 Smoke/Test Harness"
echo "==============================================================="

PROFILE_JSON="$OUTPUT_DIR/profile.json"
echo "[avx10-smoke] probing runtime profile via microbench..."
if ! cargo run --release --example microbench -- profile > "$PROFILE_JSON"; then
  echo "[avx10-smoke] microbench profile failed" >&2
  exit 1
fi

HAS_AVX10_512=$(grep -ic 'avx10_1_512:true' "$PROFILE_JSON" || true)
HAS_AVX10_256=$(grep -ic 'avx10_1_256:true' "$PROFILE_JSON" || true)

if [[ "$HAS_AVX10_512" -eq 0 && "$HAS_AVX10_256" -eq 0 ]]; then
  echo "[avx10-smoke] AVX10.1 not detected (see $PROFILE_JSON)." >&2
  if [[ "$REQUIRE" -eq 1 ]]; then
    exit 1
  else
    exit 0
  fi
fi

echo "[avx10-smoke] AVX10.1 detected (256-bit: $HAS_AVX10_256, 512-bit: $HAS_AVX10_512)."

echo "[avx10-smoke] running SIMD self-checks..."
run_cargo test --features simd-selfcheck,rust-tests --test rt-simd-selfcheck -- --nocapture

echo "[avx10-smoke] done. Artifacts stored under $OUTPUT_DIR"
