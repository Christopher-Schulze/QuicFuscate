#!/usr/bin/env bash
# Description: Developer utility: dev-uis-start.
set -Eeuo pipefail

# Start the Web Admin UI and Desktop UI dev servers as background processes.
# This is meant for local development when you want the servers to stay running
# after the command returns (for example in Codex or other non-interactive runners).
#
# PIDs are written under scripts/out/run/dev-uis/ so they can be stopped via
# scripts/utils/util-dev-uis-stop.sh.
#
# Scope boundary:
# - This script manages frontend dev servers only.
# - It does not start/stop the Rust server stack.
# - For full stack orchestration (Rust server + UI), use util-run-local-ui.sh.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: util-dev-uis-start.sh

Starts the Svelte admin UI and Svelte desktop UI dev servers as detached background
processes. PID and logs are written to scripts/out/run/dev-uis/.
Does not start the Rust server.
EOF
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t "qf-ui" 2>/dev/null; then
    echo "[dev-uis] tmux session 'qf-ui' is active (full local stack)." >&2
    echo "[dev-uis] stop it first or use util-run-local-ui.sh exclusively." >&2
    exit 2
  fi
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "[dev-uis] bun is required but not found in PATH" >&2
  exit 127
fi

PID_DIR="$ROOT/scripts/out/run/dev-uis"
mkdir -p "$PID_DIR"

# A PID alone is not ownership. The stop helper used to signal whatever now holds the
# recorded number, and it only ever signalled the wrapper shell, so Bun and Vite
# children kept running while it reported success. The record below therefore carries
# the process group, the process start time, and the command, and stop refuses to act
# on a PID whose identity does not match.
record_field() {
  local file="$1" key="$2"
  sed -n "s/^${key}=//p" "$file" 2>/dev/null | head -1
}

# Identity of a live process, as ps reports it. The start time is what distinguishes a
# reused PID from the original.
process_identity() {
  local pid="$1"
  ps -o lstart=,command= -p "$pid" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//'
}

start_one() {
  local name="$1"
  local workdir="$2"
  local cmd="$3"
  local pidfile="$PID_DIR/${name}.pid"
  local logfile="$PID_DIR/${name}.log"

  if [[ -f "$pidfile" ]]; then
    local old_pid
    old_pid="$(record_field "$pidfile" pid)"
    local old_identity
    old_identity="$(record_field "$pidfile" identity)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null \
      && [[ "$(process_identity "$old_pid")" == "$old_identity" ]]; then
      echo "[dev-uis] already running: $name (pid=$old_pid)"
      return 0
    fi
    rm -f "$pidfile"
  fi

  echo "[dev-uis] starting $name"
  local pid=""
  pid="$(
    cd "$workdir" || exit 1
    # Job control gives the background child its own process group, so stop can signal
    # the whole tree instead of only the wrapper shell. `setsid` is unavailable on
    # macOS, and this works on Bash 3.2 as well.
    set -m
    nohup bash -lc "$cmd" >"$logfile" 2>&1 &
    echo $!
  )"

  if [[ -z "$pid" ]]; then
    echo "[dev-uis] failed to start $name (no pid)" >&2
    return 1
  fi

  local pgid identity
  pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')"
  identity="$(process_identity "$pid")"
  if [[ -z "$pgid" || -z "$identity" ]]; then
    echo "[dev-uis] failed to start $name (process exited immediately; see $logfile)" >&2
    return 1
  fi

  {
    echo "pid=$pid"
    echo "pgid=$pgid"
    echo "identity=$identity"
  } >"$pidfile"

  echo "[dev-uis] $name pid=$pid pgid=$pgid log=$logfile"
}

# Web Admin UI
start_one \
  "admin-ui" \
  "$ROOT/apps/svelte-admin" \
  "bun run dev"

# Desktop UI (browser dev mode, not Tauri)
start_one \
  "desktop-ui" \
  "$ROOT/apps/svelte-desktop" \
  "bun run dev"

echo "[dev-uis] urls:"
echo "[dev-uis]   admin-ui:   http://localhost:1430"
echo "[dev-uis]   desktop-ui:   http://localhost:4173"
