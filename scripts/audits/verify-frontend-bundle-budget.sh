#!/usr/bin/env bash
# Description: Fail closed when Admin/Desktop production bundles exceed size budgets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ADMIN_BUDGET_BYTES="${QF_ADMIN_BUNDLE_BUDGET_BYTES:-4500000}"
DESKTOP_BUDGET_BYTES="${QF_DESKTOP_BUNDLE_BUDGET_BYTES:-4500000}"

measure_tree() {
  local path="$1"
  python3 - "$path" <<'PY'
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
if not root.is_dir():
    raise SystemExit(f"error: missing bundle directory: {root}")
total = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [name for name in dirnames if name not in {".git"}]
    for filename in filenames:
        total += (Path(dirpath) / filename).stat().st_size
print(total)
PY
}

fail_if_over() {
  local label="$1"
  local path="$2"
  local budget="$3"
  local size
  size="$(measure_tree "$path")"
  echo "${label}: ${size} bytes (budget ${budget})"
  if [[ "$size" -le 0 ]]; then
    echo "error: ${label} bundle measured empty" >&2
    exit 1
  fi
  if [[ "$size" -gt "$budget" ]]; then
    echo "error: ${label} bundle ${size} exceeds budget ${budget}" >&2
    exit 1
  fi
}

fail_if_over "admin" "$PROJECT_ROOT/apps/svelte-admin/build" "$ADMIN_BUDGET_BYTES"
fail_if_over "desktop" "$PROJECT_ROOT/apps/svelte-desktop/build" "$DESKTOP_BUDGET_BYTES"
