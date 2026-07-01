#!/usr/bin/env bash
# Description: Utility script: util-run-full-suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--fast] [--full]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/full-test-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

log "Running full suite into $OUTPUT_DIR"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_full_suite"; JSON_FIRST_RUN=1

# 1) Build/lint checks (short by default)
if (( FAST )); then
  run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
else
  run "$SCRIPT_DIR/../build/build-clippy-matrix.sh"
  run "$SCRIPT_DIR/../build/build-check.sh" --skip-clippy --output-dir "$OUTPUT_DIR/build-check"
fi

# 2) Core compilation + unit/integration/doc tests
if warn_if_low_disk_for_step "${QUICFUSCATE_MIN_FULL_TEST_COMPILE_GIB:-10}" "full-suite test binary precompile" "$PROJECT_ROOT"; then
  run_cargo test --no-run
fi
if (( FAST )); then
  run_cargo test --lib -- --nocapture
else
  run_cargo test --lib
  run_cargo test --doc
fi

# 3) Core integration suite (run individually, sequential)
run "$SCRIPT_DIR/../suites/test-core.sh" --output-dir "$OUTPUT_DIR/tests-core"
run "$SCRIPT_DIR/../suites/test-desktop-webadmin-rust-integration.sh" --output-dir "$OUTPUT_DIR/tests-desktop-webadmin-rust"

# 4) Core suite coverage (run individually, sequential)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../suites/test-transport.sh" --output-dir "$OUTPUT_DIR/tests-transport"
  run "$SCRIPT_DIR/../suites/test-fec.sh" --refactor --output-dir "$OUTPUT_DIR/tests-fec"
  run "$SCRIPT_DIR/../suites/test-stealth.sh" --output-dir "$OUTPUT_DIR/tests-stealth"
  run "$SCRIPT_DIR/../suites/test-profile-overrides.sh" --output-dir "$OUTPUT_DIR/tests-profile-overrides"
  run "$SCRIPT_DIR/../suites/test-profile-fuzz-parity.sh" --output-dir "$OUTPUT_DIR/tests-profile-fuzz-parity"
  run "$SCRIPT_DIR/../suites/test-fec-auto-controller-scenarios.sh" --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-scenarios"
  run "$SCRIPT_DIR/../suites/test-fec-auto-controller-proof.sh" --output-dir "$OUTPUT_DIR/tests-fec-auto-controller-proof"
  run "$SCRIPT_DIR/../suites/test-security.sh" --output-dir "$OUTPUT_DIR/tests-security"
  run "$SCRIPT_DIR/../suites/test-security-fuzzing.sh" --output-dir "$OUTPUT_DIR/tests-security-fuzzing"
  run "$SCRIPT_DIR/../suites/test-e2e-admin-web.sh" --output-dir "$OUTPUT_DIR/tests-e2e-admin-web"
  run "$SCRIPT_DIR/../suites/test-runtime-soak-chaos.sh" --output-dir "$OUTPUT_DIR/tests-runtime-soak-chaos"
else
  run "$SCRIPT_DIR/../suites/test-stealth.sh" --output-dir "$OUTPUT_DIR/tests-stealth" --fast
fi
run "$SCRIPT_DIR/../suites/test-crypto.sh" --output-dir "$OUTPUT_DIR/tests-crypto" $([[ $FAST -eq 1 ]] && echo --fast)
run "$SCRIPT_DIR/../suites/test-optimization.sh" --output-dir "$OUTPUT_DIR/tests-optimization" $([[ $FAST -eq 1 ]] && echo --fast)

if (( FAST )); then
  # Explicit fast helpers stay in sync with dedicated quick lanes.
  run "$SCRIPT_DIR/../fast/test-fast-crypto.sh" --output-dir "$OUTPUT_DIR/fast-crypto"
  run "$SCRIPT_DIR/../fast/test-fast-fec.sh" --output-dir "$OUTPUT_DIR/fast-fec"
fi

# 5) Targeted crypto smoke (aligned to test-all coverage)
if (( ! FAST )); then
  run_cargo test --release --lib aes_gcm
  run_cargo test --release --lib aegis128l
fi

# Linux-specific paths
if [[ "$(detect_os 2>/dev/null || echo unknown)" == linux ]]; then
  run_cargo test --release --features io_uring --test rt-transport-uring -- --nocapture
  run_cargo test --release --test rt-transport-xdp -- --nocapture
fi

# 6) Matrices (optional but sequential)
run "$SCRIPT_DIR/../suites/test-fec-simulation.sh" --output-dir "$OUTPUT_DIR/tests-fec-sim" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-fec-e2e-loss.sh" --output-dir "$OUTPUT_DIR/tests-fec-e2e-loss" $( ((FAST)) && echo --fast )

run "$SCRIPT_DIR/../suites/test-stealth-brain.sh" --output-dir "$OUTPUT_DIR/tests-stealth-brain" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-probe-detection.sh" --output-dir "$OUTPUT_DIR/tests-probe-detection" $( ((FAST)) && echo --fast )

# 7) E2E
run "$SCRIPT_DIR/../suites/test-e2e.sh" --output-dir "$OUTPUT_DIR/e2e" $( ((FAST)) && echo --fast )
run "$SCRIPT_DIR/../suites/test-e2e.sh" --integration --output-dir "$OUTPUT_DIR/e2e-integration" $( ((FAST)) && echo --fast )
if (( ! FAST )); then
  run "$SCRIPT_DIR/../smoke/smoke-ui-frontends.sh" --output-dir "$OUTPUT_DIR/frontend-smoke"
fi

# 8) Performance regression (fast reduces scope)
run "$SCRIPT_DIR/../suites/test-performance-regression.sh" --output-dir "$OUTPUT_DIR/tests-perf" $( ((FAST)) && echo --fast )

# 9) Audits + analysis (full profile only)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../audits/audit-all-comprehensive.sh" --output-dir "$OUTPUT_DIR/audit"
  run "$SCRIPT_DIR/../../utils/util-analyze-codebase.sh" > "$OUTPUT_DIR/analysis.txt"
fi

# 10) Dedicated benches (full profile only)
if (( ! FAST )); then
  if cargo bench --no-run --features benches >/dev/null 2>&1; then
    run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth.sh" --output-dir "$OUTPUT_DIR/bench-stealth"
  else
    warn "Skipping stealth benches"
  fi
  run "$SCRIPT_DIR/../../benchmarks/suites/bench-fec-simulation.sh" --output-dir "$OUTPUT_DIR/bench-fec-sim"
  run "$SCRIPT_DIR/../../benchmarks/suites/bench-stealth-brain.sh" --output-dir "$OUTPUT_DIR/bench-stealth-brain"
fi

# 5) Coverage summary (full profile only)
if (( ! FAST )); then
  run "$SCRIPT_DIR/../analysis/analysis-coverage-summary.sh" --output-dir "$OUTPUT_DIR/coverage"
fi

echo -e "\n[OK] Full suite complete. Artifacts: $OUTPUT_DIR"
json_end "$JSON"
