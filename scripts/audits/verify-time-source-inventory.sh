#!/usr/bin/env bash
# Description: Verify and emit the complete direct-clock inventory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

exec python3 "$SCRIPT_DIR/verify-time-source-inventory.py" --root "$PROJECT_ROOT" "$@"
