#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-environment-json.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

run_contract() {
  local suite="$1"
  local output_dir="$TEMP_ROOT/$suite"
  QUICFUSCATE_JSON_CONTRACT_TEST=1 \
    bash "$PROJECT_ROOT/scripts/tests/suites/$suite.sh" --output-dir "$output_dir"
}

run_contract test-optimization
run_contract test-performance-regression
run_contract test-security-fuzzing

python3 - "$TEMP_ROOT" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
for suite in ("test-optimization", "test-performance-regression", "test-security-fuzzing"):
    candidates = list((root / suite).glob("*.json"))
    assert len(candidates) == 1, (suite, candidates)
    with candidates[0].open(encoding="utf-8") as handle:
        report = json.load(handle)
    fixture = next(item for item in report["items"] if item["name"] == "json-contract-fixture")
    assert fixture["environment"] == {"fixture": "non-empty"}, fixture

print("PASS: suite environment JSON contract fixtures")
PY
