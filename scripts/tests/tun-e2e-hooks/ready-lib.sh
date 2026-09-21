#!/usr/bin/env bash
# Shared helpers for tun-e2e ready hooks (TODO-1025).
# Sourced by udp-ready.sh / tcp-ready.sh. Not invoked directly.

set -euo pipefail

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$HOOK_DIR/../../.." && pwd)}"

fail() {
  echo "FAIL: e2e ready hook: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

qtun_counters() {
  local ns="$1"
  echo "=== qtun0 ${ns} ==="
  ip netns exec "$ns" ip -s link show qtun0 || echo "qtun0 missing in ${ns}"
}

qtun_tx_dropped() {
  local ns="$1"
  ip netns exec "$ns" ip -json -s link show qtun0 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    print("missing")
    raise SystemExit(0)
data = json.loads(raw)
entry = data[0] if isinstance(data, list) else data
stats = entry.get("stats64") or entry.get("stats") or {}
tx = stats.get("tx") or {}
print(tx.get("dropped", "missing"))
' || echo missing
}

stop_pid() {
  local pid="${1:-}"
  if [ -z "$pid" ]; then
    return
  fi
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

prepare_evidence_dir() {
  local tag="$1"
  if [ -n "${QF_E2E_HOOK_OUTPUT_DIR:-}" ]; then
    if [ "${QF_E2E_HOOK_OUTPUT_DIR#/}" = "$QF_E2E_HOOK_OUTPUT_DIR" ]; then
      fail "QF_E2E_HOOK_OUTPUT_DIR must be an absolute path"
    fi
    EVIDENCE_DIR="$QF_E2E_HOOK_OUTPUT_DIR"
  else
    EVIDENCE_DIR="/tmp/qf-e2e-hooks"
  fi
  mkdir -p "$EVIDENCE_DIR"
  EVIDENCE_FILE="$EVIDENCE_DIR/${tag}.evidence"
  if [ -e "$EVIDENCE_FILE" ]; then
    fail "refusing to overwrite evidence path: $EVIDENCE_FILE"
  fi
}

emit() {
  printf '%s\n' "$*" | tee -a "$EVIDENCE_FILE"
}
