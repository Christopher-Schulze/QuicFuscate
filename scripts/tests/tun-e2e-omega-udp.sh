#!/usr/bin/env bash
# Repo-relative Omega UDP evidence driver (TODO-1025).
# Leaves tun-e2e-netns.sh default behavior unchanged: this wrapper is the
# only path that auto-selects the versioned ready hook.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
HOOK="$SCRIPT_DIR/tun-e2e-hooks/udp-ready.sh"

if [ ! -x "$HOOK" ]; then
  echo "FAIL: missing executable ready hook: $HOOK" >&2
  exit 1
fi

export PROJECT_ROOT
export QF_E2E_READY_HOOK="${QF_E2E_READY_HOOK:-$HOOK}"
export TAG="${TAG:-udp}"
export UDPRATE="${UDPRATE:-60M}"
export DURATION="${DURATION:-15}"
export QF_E2E_HOOK_OUTPUT_DIR="${QF_E2E_HOOK_OUTPUT_DIR:-/tmp/qf-e2e-hooks}"
if [ -n "${QF_E2E_FEC_CONFIG:-}" ]; then
  export QF_E2E_FEC_CONFIG
fi

exec "$SCRIPT_DIR/tun-e2e-netns.sh" "$@"
