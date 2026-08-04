#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/failing-cargo"
OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-bench-preflight.XXXXXX")"
trap 'rm -rf "$OUTPUT_DIR"' EXIT

set +e
PATH="$FIXTURE_DIR:$PATH" \
  QUICFUSCATE_BENCH_PREFLIGHT_CONTRACT_TEST=1 \
  bash "$PROJECT_ROOT/scripts/tests/utils/util-run-full-suite.sh" --full --output-dir "$OUTPUT_DIR"
RC=$?
set -e
[[ "$RC" -eq 1 ]] || {
  printf 'expected benchmark preflight failure, got rc=%s\n' "$RC" >&2
  exit 1
}

python3 - "$OUTPUT_DIR/results.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
item = next(item for item in report["items"] if item["name"] == "bench-stealth-preflight")
assert item["status"] == "FAIL", item
assert item["command_rc"] == 42, item
assert item["result"] == "FAIL", item
print("PASS: full-suite benchmark preflight fixture")
PY
