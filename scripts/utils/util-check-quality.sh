#!/usr/bin/env bash
# Description: General utility: util-check-quality.
set -euo pipefail

# Quality assurance script for QuicFuscate (robust + artifacts).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../tests/lib/lib-common.sh" || { echo "ERROR: lib-common.sh not found at $SCRIPT_DIR/../tests/lib/lib-common.sh" >&2; exit 1; }

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Quality check"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/quality-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/check_quality.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_check_quality"; JSON_FIRST_RUN=1

echo "[INFO] QuicFuscate Quality Check"
print_system_banner || true

info "[INFO] Building with strict warnings..."
run_cargo build --release

info "[INFO] Running unit tests..."
# Release-quality gate: validate the shipping test surface.
run_cargo test --release --quiet

if command -v cargo-clippy &> /dev/null; then
  info "[INFO] Running clippy analysis..."
  if [[ "${CLIPPY_ALL_FEATURES:-0}" == "1" ]]; then
    run cargo clippy --workspace --all-targets --all-features -- -D warnings | tee "$OUTPUT_DIR/clippy.txt"
  else
    # Default release hygiene: validate the shipping surface, not experimental optional features.
    run cargo clippy --workspace --all-targets -- -D warnings | tee "$OUTPUT_DIR/clippy.txt"
  fi
else
  warn "cargo-clippy not available, skipping"
fi

if command -v cargo-fmt &> /dev/null; then
  info "[INFO] Checking code formatting..."
  run cargo fmt --check | tee "$OUTPUT_DIR/fmt.txt"
else
  warn "rustfmt not available, skipping"
fi

info "[INFO] Performance smoke test..."
run_cargo test --release --lib test_product_fec_default_is_auto --quiet || true

if command -v cargo-audit &> /dev/null; then
  info "[INFO] Security audit..."
  run cargo audit | tee "$OUTPUT_DIR/audit.txt" || true
else
  warn "cargo-audit not available, skipping"
fi

# ShellCheck across all scripts if available
if command -v shellcheck >/dev/null 2>&1; then
  info "[INFO] ShellCheck analysis across scripts..."
  SC_OUT="$OUTPUT_DIR/shellcheck.txt"
  mapfile -t SHS < <(find "$SCRIPT_DIR/../.." -type f -name '*.sh' -not -path '*/out/*' | sort)
  : > "$SC_OUT"
  SC_ISSUES=0
  for shf in "${SHS[@]}"; do
    shellcheck -S warning -x "$shf" >> "$SC_OUT" 2>&1 || true
  done
  SC_ISSUES=$(grep -E "SC[0-9]+:" "$SC_OUT" | wc -l | tr -d ' ')
  info "ShellCheck issues: $SC_ISSUES (see $SC_OUT)"
  qf_json_append_object "$JSON" "shellcheck_issues=int:$SC_ISSUES"
else
  warn "shellcheck not installed; skipping"
fi

info "[INFO] Script consistency analysis..."
run bash scripts/tests/analysis/analysis-scripts-quality.sh --output-dir "$OUTPUT_DIR/scripts-quality" | tee "$OUTPUT_DIR/scripts-quality.txt"
run bash scripts/tests/analysis/analysis-suite-matrix.sh --output-dir "$OUTPUT_DIR/suite-matrix" | tee "$OUTPUT_DIR/suite-matrix.txt"

echo ""; echo "[OK] Quality check completed. Artifacts: $OUTPUT_DIR"
json_end "$JSON"
