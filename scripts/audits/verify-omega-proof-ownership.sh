#!/usr/bin/env bash
# Description: Run the read-only, fail-closed Omega proof ownership preflight.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
exec python3 -B "$SCRIPT_DIR/verify-omega-proof-ownership.py" \
  --project-root "$PROJECT_ROOT" "$@"
