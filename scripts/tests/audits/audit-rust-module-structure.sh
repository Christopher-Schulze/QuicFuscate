#!/usr/bin/env bash
# Description: Reject oversized Rust source files and textual source assembly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
MAX_LINES="${QF_RUST_MODULE_MAX_LINES:-2000}"

case "${1:-}" in
  "") ;;
  -h|--help|help)
    printf '%s\n' "Usage: $(basename "$0")"
    printf '%s\n' 'Rejects Rust files above QF_RUST_MODULE_MAX_LINES physical lines and all source include! assembly.'
    exit 0
    ;;
  *)
    printf 'Unknown argument: %s\n' "$1" >&2
    exit 2
    ;;
esac

if [[ ! "$MAX_LINES" =~ ^[1-9][0-9]*$ ]]; then
  printf 'FAIL: QF_RUST_MODULE_MAX_LINES must be a positive integer, got %q\n' "$MAX_LINES" >&2
  exit 2
fi

exec python3 - "$PROJECT_ROOT" "$MAX_LINES" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
max_lines = int(sys.argv[2])
source_roots = tuple(path for path in (root / "src", root / "crates") if path.is_dir())
if not source_roots:
    print("FAIL: no Rust source roots found under src/ or crates/", file=sys.stderr)
    raise SystemExit(1)

rust_files = sorted(path for source_root in source_roots for path in source_root.rglob("*.rs"))
oversized: list[tuple[str, int]] = []
textual_assembly: list[tuple[str, int]] = []
include_pattern = re.compile(r"\binclude!\s*\(")

for path in rust_files:
    relative = path.relative_to(root).as_posix()
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > max_lines:
        oversized.append((relative, len(lines)))
    for line_number, line in enumerate(lines, start=1):
        code = line.split("//", 1)[0]
        if include_pattern.search(code):
            textual_assembly.append((relative, line_number))

if oversized or textual_assembly:
    for path, line_count in oversized:
        print(f"OVERSIZED: {path} lines={line_count} limit={max_lines}", file=sys.stderr)
    for path, line_number in textual_assembly:
        print(f"TEXTUAL_ASSEMBLY: {path}:{line_number} uses include!", file=sys.stderr)
    print(
        "FAIL: Rust module structure "
        f"files={len(rust_files)} oversized={len(oversized)} include_assembly={len(textual_assembly)}",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(
    "PASS: Rust module structure "
    f"files={len(rust_files)} max_lines={max_lines} oversized=0 include_assembly=0"
)
PY
