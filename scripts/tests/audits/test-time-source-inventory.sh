#!/usr/bin/env bash
# Description: Verify that JavaScript template interpolations remain auditable.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  printf '%s\n' 'Usage: test-time-source-inventory.sh'
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="$SCRIPT_DIR/../../audits/verify-time-source-inventory.py"

python3 - "$INVENTORY" <<'PY'
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
mask_javascript = namespace["mask_javascript"]

source = """
const ignored = `Date.now() ${"Date.now()"}`;
const direct = `${Date.now()}-${Math.random()}`;
const nested = `${`Date.now() ${performance.now()}`}`;
"""
masked = mask_javascript(source)
lines = masked.splitlines()

assert "Date.now()" not in lines[1], masked
assert "Date.now()" in lines[2], masked
assert "performance.now()" in lines[3], masked
assert '"Date.now()"' not in lines[1], masked
PY

printf '%s\n' 'PASS: JavaScript template interpolation remains auditable'
