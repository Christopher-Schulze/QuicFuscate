#!/usr/bin/env bash
# TCP evidence wrapper for tun-e2e-netns.sh (TODO-1019 / TODO-1025).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export QF_E2E_READY_HOOK="${QF_E2E_READY_HOOK:-$SCRIPT_DIR/tun-e2e-hooks/tcp-ready.sh}"
export TAG="${TAG:-tcp}"
export DURATION="${DURATION:-15}"
export QF_E2E_HOOK_OUTPUT_DIR="${QF_E2E_HOOK_OUTPUT_DIR:-/tmp/qf-e2e-hooks}"

exec "$SCRIPT_DIR/tun-e2e-netns.sh" "$@"
