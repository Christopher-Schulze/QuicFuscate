#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/secret-scope"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-secret-scope.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

mkdir -p "$TEMP_ROOT/src" "$TEMP_ROOT/scripts/fixtures"
cp "$FIXTURE_DIR/src/inline.rs" "$TEMP_ROOT/src/inline.rs"
cp "$FIXTURE_DIR/scripts/shipped.sh" "$TEMP_ROOT/scripts/shipped.sh"
cp "$FIXTURE_DIR/scripts/tests/fixture.sh" "$TEMP_ROOT/scripts/fixtures/fixture.sh"

python3 "$SCRIPT_DIR/audit-secret-scope.py" --root "$TEMP_ROOT" > "$TEMP_ROOT/result.json"
python3 - "$TEMP_ROOT/result.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)

assert report["secret_count"] == 1, report
assert report["locations"] == [{"kind": "secret_assignment", "line": 2, "path": "scripts/shipped.sh"}], report
assert report["excluded_files"] == 1, report
PY

printf '%s\n' 'PASS: secret-scope audit fixtures'
