#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures/rust-scope"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-rust-scope.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

mkdir -p "$TEMP_ROOT/src/tests"
cp "$FIXTURE_DIR/src/production.rs" "$TEMP_ROOT/src/production.rs"
cp "$FIXTURE_DIR/src/inline_tests.rs" "$TEMP_ROOT/src/inline_tests.rs"
cp "$FIXTURE_DIR/src/tests/ignored.rs" "$TEMP_ROOT/src/tests/ignored.rs"

python3 "$SCRIPT_DIR/audit-rust-scope.py" --root "$TEMP_ROOT" > "$TEMP_ROOT/result.json"
python3 - "$TEMP_ROOT/result.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)

assert report["files_scanned"] == 3
assert report["production_files"] == 2
assert report["excluded_files"] == 1
assert report["unsafe_count"] == 1, report
assert report["leak_pattern_count"] == 2, report
assert all(item["path"] == "src/production.rs" for item in report["locations"]), report
PY

printf '%s\n' 'PASS: Rust production-scope audit fixtures'
