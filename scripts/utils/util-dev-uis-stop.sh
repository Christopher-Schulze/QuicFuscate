#!/usr/bin/env bash
# Description: Developer utility: dev-uis-stop.
set -Eeuo pipefail

# Stop dev servers started by scripts/utils/util-dev-uis-start.sh.
#
# Scope boundary:
# - Stops only detached frontend dev servers tracked in scripts/out/run/dev-uis/.
# - Does not manage tmux full-stack sessions; use util-stop-local-ui.sh for that.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: util-dev-uis-stop.sh

Stops background UI dev servers started by util-dev-uis-start.sh using PID files
from scripts/out/run/dev-uis/.
Does not stop full stack tmux sessions.
EOF
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PID_DIR="$ROOT/scripts/out/run/dev-uis"

stop_one() {
  local name="$1"
  local pidfile="$PID_DIR/${name}.pid"

  if [[ ! -f "$pidfile" ]]; then
    echo "[dev-uis] not running: $name (missing pid file)"
    return 0
  fi

  local pid pgid recorded_identity
  pid="$(sed -n 's/^pid=//p' "$pidfile" 2>/dev/null | head -1)"
  pgid="$(sed -n 's/^pgid=//p' "$pidfile" 2>/dev/null | head -1)"
  recorded_identity="$(sed -n 's/^identity=//p' "$pidfile" 2>/dev/null | head -1)"

  if [[ -z "$pid" ]]; then
    rm -f "$pidfile"
    echo "[dev-uis] not running: $name (unreadable record)"
    return 0
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pidfile"
    echo "[dev-uis] not running: $name (stale pid=$pid)"
    return 0
  fi

  # A live PID is not proof it is ours. PIDs are reused, and signalling whatever now
  # holds the number is how a helper like this kills an unrelated process.
  local current_identity
  current_identity="$(ps -o lstart=,command= -p "$pid" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"
  if [[ -n "$recorded_identity" && "$current_identity" != "$recorded_identity" ]]; then
    echo "[dev-uis] refusing to signal pid=$pid for $name: identity does not match the record" >&2
    echo "[dev-uis]   recorded: $recorded_identity" >&2
    echo "[dev-uis]   current:  $current_identity" >&2
    rm -f "$pidfile"
    return 1
  fi

  # Signal the process group, not just the wrapper shell. Killing the wrapper alone
  # left Bun and Vite running while this reported the service stopped.
  local target="$pid"
  local group=0
  if [[ -n "$pgid" ]] && kill -0 -- "-$pgid" 2>/dev/null; then
    target="-$pgid"
    group=1
  fi

  echo "[dev-uis] stopping $name pid=$pid${pgid:+ pgid=$pgid}"
  kill -- "$target" 2>/dev/null || true

  local waited=0
  while ((waited < 40)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.25
    waited=$((waited + 1))
  done

  if kill -0 "$pid" 2>/dev/null; then
    echo "[dev-uis] force stopping $name pid=$pid"
    kill -9 -- "$target" 2>/dev/null || true
    sleep 0.5
  fi

  rm -f "$pidfile"

  # Report survivors instead of claiming success. A surviving descendant holds the dev
  # port and the next start would fail for a reason this helper had already hidden.
  if ((group)) && kill -0 -- "-$pgid" 2>/dev/null; then
    echo "[dev-uis] FAILED to stop $name: processes remain in pgid=$pgid" >&2
    ps -o pid=,command= -g "$pgid" 2>/dev/null | sed 's/^/[dev-uis]   /' >&2 || true
    return 1
  fi
  if kill -0 "$pid" 2>/dev/null; then
    echo "[dev-uis] FAILED to stop $name: pid=$pid is still alive" >&2
    return 1
  fi

  echo "[dev-uis] stopped $name"
}

STOP_FAILURES=0
stop_one "desktop-ui" || STOP_FAILURES=$((STOP_FAILURES + 1))
stop_one "admin-ui" || STOP_FAILURES=$((STOP_FAILURES + 1))

if ((STOP_FAILURES)); then
  echo "[dev-uis] ${STOP_FAILURES} helper(s) did not stop cleanly" >&2
  exit 1
fi
