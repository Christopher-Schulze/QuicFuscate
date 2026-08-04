#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/dialect-validation"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-dialects.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

cp -R "$FIXTURE_DIR/." "$TEMP_ROOT/"
python3 "$SCRIPT_DIR/analysis-dialect-validation.py" --root "$TEMP_ROOT" > "$TEMP_ROOT/result.json"
python3 - "$TEMP_ROOT/result.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)

items = {item["path"]: item for item in report["items"]}
assert items["config/valid.json"]["status"] == "PASS", report
assert items["config/valid.yaml"]["status"] == "PASS", report
assert items["config/valid.toml"]["status"] == "PASS", report
assert items["tsconfig.json"]["status"] == "PASS", report
assert items["scripts/valid.py"]["status"] == "PASS", report
assert items["scripts/valid.sh"]["status"] == "PASS", report
assert items["config/invalid.json"]["status"] == "FAIL", report
assert items["scripts/invalid.py"]["status"] == "FAIL", report
assert items["scripts/invalid.sh"]["status"] == "FAIL", report
assert items["scripts/unknown.ps1"]["status"] in {"UNAVAILABLE", "PASS"}, report
assert report["status"] == "FAIL", report
PY

printf '%s\n' 'PASS: dialect validation fixtures'
