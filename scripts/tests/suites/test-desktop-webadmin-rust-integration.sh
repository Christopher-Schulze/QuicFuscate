#!/usr/bin/env bash
# Description: Test suite runner: desktop unit + web-admin unit + rust integration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--verbose]"
      exit 0
      ;;
    *) break;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"

echo "==============================================================="
echo "  Targeted Validation Suite"
echo "  - Desktop Check"
echo "  - Desktop Unit"
echo "  - Web-Admin Check"
echo "  - Web-Admin Unit"
echo "  - Rust Integration (5 targeted targets)"
echo "==============================================================="
echo "Output: $OUTPUT_DIR"

run_verified_rust_target() {
  local target="$1"
  local expected_test_name="$2"
  local feature_set="$3"
  qf_cargo_test_run_expect \
    "$OUTPUT_DIR/${target}.log" "test:${target}" "$feature_set" \
    "$expected_test_name" "$expected_test_name" \
    --test "$target" -- --nocapture
}

run bash -lc "cd \"$PROJECT_ROOT/apps/svelte-desktop\" && bun run check"
run bash -lc "cd \"$PROJECT_ROOT/apps/svelte-desktop\" && bun run test:unit"
run bash -lc "cd \"$PROJECT_ROOT/apps/svelte-admin\" && bun run check"
run bash -lc "cd \"$PROJECT_ROOT/apps/svelte-admin\" && bun run test:unit"
run_verified_rust_target \
  it-engine-control-plane \
  test_control_plane_getters_and_runtime_setters \
  rust-tests
run_verified_rust_target \
  it-interface-capabilities \
  test_tun_capabilities_report_matches_target \
  rust-tests
run_verified_rust_target \
  it-orchestrator-runtime-activation \
  test_orchestrator_runtime_activation_and_signal_flow \
  rust-tests,orchestrator
run_verified_rust_target \
  it-qkey-auth-integration \
  qkey_http3_auth_accepts_valid_and_rejects_invalid_token \
  rust-tests
run_verified_rust_target \
  it-stealth-mode-matrix \
  test_mode_feature_matrix_core_expectations \
  rust-tests

echo
echo "[OK] Targeted validation suite passed. Log: $LOG_FILE"
