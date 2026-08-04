#!/usr/bin/env bash
# Description: Build and validate fail-closed Graphify relationship evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
EVIDENCE_SCRIPT="$SCRIPT_DIR/verify-graphify-evidence.py"

if [[ ! -f "$EVIDENCE_SCRIPT" ]]; then
  echo "error: missing Graphify evidence implementation: $EVIDENCE_SCRIPT" >&2
  exit 1
fi

GRAPHIFY_PYTHON="${GRAPHIFY_PYTHON:-}"
if [[ -z "$GRAPHIFY_PYTHON" && -f "$PROJECT_ROOT/graphify-out/.graphify_python" ]]; then
  GRAPHIFY_PYTHON="$(<"$PROJECT_ROOT/graphify-out/.graphify_python")"
fi
if [[ -z "$GRAPHIFY_PYTHON" && -n "$(command -v graphify 2>/dev/null || true)" ]]; then
  GRAPHIFY_BIN="$(command -v graphify)"
  GRAPHIFY_PYTHON="$(head -1 "$GRAPHIFY_BIN" | sed 's/^#!//; s/ -E$//')"
fi
if [[ -z "$GRAPHIFY_PYTHON" ]]; then
  GRAPHIFY_PYTHON="$(command -v python3 || true)"
fi

if [[ -z "$GRAPHIFY_PYTHON" || ! -x "$GRAPHIFY_PYTHON" ]]; then
  echo "error: no executable Python interpreter is available for Graphify evidence" >&2
  exit 2
fi

exec "$GRAPHIFY_PYTHON" "$EVIDENCE_SCRIPT" --project-root "$PROJECT_ROOT" "$@"
