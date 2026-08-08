#!/usr/bin/env bash
# Description: Offline smoke check for the engine_basic example.
#
# The example is the copy-paste entry point for embedding the engine, so two of its
# properties are contractual rather than cosmetic: it must not touch the network unless
# asked, and it must not weaken peer verification unless asked. This proves both, plus
# that its documented no-server run actually completes.
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
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR]"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/smoke/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
OFFLINE_LOG="$OUTPUT_DIR/offline.log"

echo "> running engine_basic with no arguments (must not connect)"
if ! cargo run --quiet --example engine_basic > "$OFFLINE_LOG" 2>&1; then
  echo "[FAIL] the default example run must succeed without a server" >&2
  tail -20 "$OFFLINE_LOG" >&2
  exit 1
fi

if ! grep -q "pass --connect to attempt one" "$OFFLINE_LOG"; then
  echo "[FAIL] the default run must state that it skipped the connection" >&2
  exit 1
fi
if ! grep -q "Verify peer: true" "$OFFLINE_LOG"; then
  echo "[FAIL] peer verification must stay enabled by default" >&2
  exit 1
fi
if grep -qi "Connected!" "$OFFLINE_LOG"; then
  echo "[FAIL] the default run must not open a connection" >&2
  exit 1
fi

echo "> running engine_basic --insecure-no-verify (must warn and disable)"
INSECURE_LOG="$OUTPUT_DIR/insecure.log"
cargo run --quiet --example engine_basic -- --insecure-no-verify > "$INSECURE_LOG" 2>&1
if ! grep -q "WARNING: --insecure-no-verify" "$INSECURE_LOG"; then
  echo "[FAIL] the insecure opt-in must warn visibly" >&2
  exit 1
fi
if ! grep -q "Verify peer: false" "$INSECURE_LOG"; then
  echo "[FAIL] the insecure opt-in must actually disable verification" >&2
  exit 1
fi

echo "> running engine_basic with an unknown option (must fail)"
if cargo run --quiet --example engine_basic -- --definitely-not-an-option \
    > "$OUTPUT_DIR/bad-option.log" 2>&1; then
  echo "[FAIL] an unknown option must not be ignored" >&2
  exit 1
fi

echo "[OK] engine_basic offline contract holds"
