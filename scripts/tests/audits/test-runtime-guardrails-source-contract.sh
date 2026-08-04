#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="$SCRIPT_DIR/fixtures/runtime-guardrails/tun-e2e-scoped-pid.sh"

rg -n -- '^[[:space:]]*SERVER_PID=\$![[:space:]]*$' "$FIXTURE" >/dev/null
rg -n -- '^[[:space:]]*CLIENT_PID=\$![[:space:]]*$' "$FIXTURE" >/dev/null
rg -n -- 'stop_owned_process "\$CLIENT_PID"' "$FIXTURE" >/dev/null
rg -n -- 'stop_owned_process "\$SERVER_PID"' "$FIXTURE" >/dev/null
rg -n -- '^trap cleanup_on_exit EXIT$' "$FIXTURE" >/dev/null

printf '%s\n' 'PASS: runtime guardrail scoped PID fixture'
