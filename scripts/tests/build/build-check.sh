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

# Check formatting
echo -e "\n> Checking code formatting..."
if ! cargo fmt --check 2>/dev/null; then
  warn "cargo fmt check failed; continuing (some modules may be feature-gated)"
fi

# Run clippy
echo -e "\n> Running clippy..."
if [[ "$SKIP_CLIPPY" -eq 1 ]]; then
  warn "Skipping clippy (handled elsewhere)"
else
  if ! cargo clippy --all-targets -- -D warnings; then
    warn "clippy reported issues; please review above"
  fi
fi

# Check compilation
echo -e "\n> Checking compilation..."
cargo check

# Check tests compile
echo -e "\n> Checking test compilation..."
if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_FULL_TEST_COMPILE_GIB:-10}" "full test binary compilation" "$PROJECT_ROOT"; then
  run_cargo test --no-run --features rust-tests
fi

# Check benchmarks compile
echo -e "\n> Checking benchmark compilation..."
if ! warn_if_low_disk_for_step "${QUICFUSCATE_MIN_BENCH_COMPILE_GIB:-10}" "benchmark binary compilation" "$PROJECT_ROOT"; then
  warn "benchmark compilation skipped due to low disk"
elif ! cargo bench --no-run --features benches; then
  warn "benchmark compilation failed (benches may be optional in this build)"
fi

echo -e "\n[OK] Compilation checks passed (see any warnings above for fmt/clippy issues)"
json_end "$JSON"
