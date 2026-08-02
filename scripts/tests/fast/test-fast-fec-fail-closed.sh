#!/usr/bin/env bash
# Description: Contract test: fast-fec failure propagation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAST_FEC="$SCRIPT_DIR/test-fast-fec.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR]"
      echo "Proves that a real Cargo failure cannot produce a green fast-fec result."
      exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
  shift
done

[[ -x "$FAST_FEC" ]] || { echo "fast-fec helper is not executable: $FAST_FEC" >&2; exit 1; }

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-fast-fec-contract.XXXXXX")"
else
  mkdir -p "$OUTPUT_DIR"
fi

CONTRACT_LOG="$OUTPUT_DIR/contract.log"
RESULTS_JSON="$OUTPUT_DIR/results.json"

set +e
"$FAST_FEC" --output-dir "$OUTPUT_DIR/helper" --rustflags "-Z quicfuscate_fast_fec_failure" > "$CONTRACT_LOG" 2>&1
helper_status=$?
set -e

[[ "$helper_status" -ne 0 ]] || {
  echo "fast-fec unexpectedly returned success under a real invalid-RUSTFLAGS failure" >&2
  exit 1
}
[[ ! -s "$OUTPUT_DIR/helper/results.json" ]] || RESULTS_JSON="$OUTPUT_DIR/helper/results.json"
[[ -f "$RESULTS_JSON" ]] || { echo "missing bounded fast-fec result artifact" >&2; exit 1; }

if rg -F '[OK] FEC tests complete' "$CONTRACT_LOG" >/dev/null; then
  echo "fast-fec emitted a green completion marker after the injected failure" >&2
  exit 1
fi

python3 - "$RESULTS_JSON" "$helper_status" <<'PY'
import json
import sys
from pathlib import Path

result_path = Path(sys.argv[1])
helper_status = int(sys.argv[2])
data = json.loads(result_path.read_text())
items = data.get("items", [])
focused = [item for item in items if item.get("name") == "focused_fec_filter"]
if not focused:
    raise SystemExit("missing focused FEC failure record")
first = focused[0]
if first.get("status") not in {"FAIL", "UNAVAILABLE"}:
    raise SystemExit(f"unexpected focused result status: {first.get('status')!r}")
if int(first.get("command_status", 0)) == 0:
    raise SystemExit("focused failure record lost its nonzero command status")
if helper_status == 0:
    raise SystemExit("helper status was zero")
if any(item.get("name") == "fec_bench_compile" for item in items):
    raise SystemExit("bench smoke ran after the focused failure")
PY

echo "[PASS] fast-fec fail-closed negative contract: helper_status=$helper_status result=$RESULTS_JSON"
