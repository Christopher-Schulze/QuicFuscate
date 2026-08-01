#!/usr/bin/env bash
# Description: Unified FEC test dispatcher (TODO-174 Phase 2).
#
# Consolidates all FEC-related test scripts behind a single entry point.
# Use --mode to select which test dimension to run, or omit it to run all.
#
# Modes:
#   internal     - FEC internal machine-room tests (modes, adaptive, GF, Rayon, stress)
#   simulation   - FEC simulation parameter matrix (mode x loss x thread x GF16 x cadence)
#   e2e-loss     - FEC model-loss matrix via fec_sim; native QUIC/TUN proof is separate
#   controller   - FEC auto-controller scenario suite (clean-efficiency, escalation, etc.)
#   proof        - FEC auto-controller proof (scenarios + bench iterations combined)
#   fast         - Quick FEC smoke (unit tests + bench compile check)
#   all          - Run all modes sequentially (default)
#
# All flags after --mode are passed through to the underlying script.
# Common pass-through flags: --output-dir, --fast, --full, --verbose
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="all"
PASSTHROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: test-fec-all.sh [--mode MODE] [passthrough-flags...]

Unified FEC test dispatcher. Runs one or all FEC test dimensions.

Modes:
  internal     FEC internal machine-room tests
  simulation   FEC simulation parameter matrix
  e2e-loss     FEC end-to-end loss recovery
  controller   FEC auto-controller scenarios
  proof        FEC auto-controller proof (scenarios + bench)
  fast         Quick FEC smoke tests
  all          Run all modes sequentially (default)

All other flags are passed through to the underlying script.
Common flags: --output-dir DIR, --fast, --full, --verbose
EOF
      exit 0
      ;;
    *)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

resolve_script() {
  case "$1" in
    internal)   echo "$SCRIPT_DIR/test-fec.sh" ;;
    simulation) echo "$SCRIPT_DIR/test-fec-simulation.sh" ;;
    e2e-loss)   echo "$SCRIPT_DIR/test-fec-e2e-loss.sh" ;;
    controller) echo "$SCRIPT_DIR/test-fec-auto-controller-scenarios.sh" ;;
    proof)      echo "$SCRIPT_DIR/test-fec-auto-controller-proof.sh" ;;
    fast)       echo "$SCRIPT_DIR/../fast/test-fast-fec.sh" ;;
    *)          echo "" ;;
  esac
}

if [[ "$MODE" != "all" ]]; then
  SCRIPT="$(resolve_script "$MODE")"
  if [[ -z "$SCRIPT" ]]; then
    echo "Unknown mode: $MODE" >&2
    echo "Valid modes: internal, simulation, e2e-loss, controller, proof, fast, all" >&2
    exit 2
  fi
  exec bash "$SCRIPT" "${PASSTHROUGH_ARGS[@]}"
fi

# all mode: run each dimension sequentially, collect failures
echo "==============================================================="
echo "  FEC Unified Test Suite - All Modes"
echo "==============================================================="

FAILURES=0
MODES_RUN=0

for m in fast internal simulation e2e-loss controller proof; do
  SCRIPT="$(resolve_script "$m")"
  echo ""
  echo "--- [$m] $(basename "$SCRIPT") ---"
  MODES_RUN=$((MODES_RUN + 1))
  if bash "$SCRIPT" "${PASSTHROUGH_ARGS[@]}"; then
    echo "--- [$m] OK ---"
  else
    echo "--- [$m] FAILED ---"
    FAILURES=$((FAILURES + 1))
  fi
done

echo ""
echo "==============================================================="
echo "  FEC Unified Summary: $((MODES_RUN - FAILURES))/$MODES_RUN passed"
echo "==============================================================="

if [[ $FAILURES -gt 0 ]]; then
  echo "[FAIL] $FAILURES FEC mode(s) failed"
  exit 1
fi

echo "[OK] All FEC modes passed"
exit 0
