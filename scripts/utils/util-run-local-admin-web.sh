#!/usr/bin/env bash
# Description: Developer utility: run-local-admin-web.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: util-run-local-admin-web.sh [--admin-port N] [--server-port N]

Starts a tmux session with a single admin window:
- Rust server + built web admin assets

The runtime config and auth store live under
`scripts/out/run/admin-web/` and are reset on each start so the local
credentials remain deterministic (`admin` / `123`).

Options:
  --admin-port N   Admin UI bind port (default: 9000)
  --server-port N  QUIC server bind port (default: 4433)
  -h, --help       Show help
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SESSION="qf-admin-web"
PID_DIR="$ROOT/scripts/out/run/admin-web"
RUNTIME_CONFIG="$PID_DIR/server.toml"
RUNTIME_AUTH="$PID_DIR/admin-auth.json"

ADMIN_PORT="${ADMIN_PORT:-9000}"
SERVER_PORT="${SERVER_PORT:-4433}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-port) ADMIN_PORT="${2:-}"; shift 2 ;;
    --server-port) SERVER_PORT="${2:-}"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] || { echo "Invalid --admin-port: $ADMIN_PORT" >&2; exit 2; }
[[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || { echo "Invalid --server-port: $SERVER_PORT" >&2; exit 2; }

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required but not found in PATH" >&2
  exit 127
fi

if [[ -f "$ROOT/scripts/out/run/dev-uis/admin-ui.pid" || -f "$ROOT/scripts/out/run/dev-uis/desktop-ui.pid" ]]; then
  echo "Detected detached UI dev servers in $ROOT/scripts/out/run/dev-uis." >&2
  echo "Stop them first via scripts/utils/util-dev-uis-stop.sh, then run this tmux admin-web script." >&2
  exit 2
fi

CERT_PATH="$(ls -1t "${ROOT}"/config/local/dev-certs/*.crt 2>/dev/null | head -n 1 || true)"
KEY_PATH="$(ls -1t "${ROOT}"/config/local/dev-certs/*.key 2>/dev/null | head -n 1 || true)"
if [[ -z "$CERT_PATH" || -z "$KEY_PATH" ]]; then
  CERT_PATH="$(ls -1t "${ROOT}"/config/dev-certs/*.crt 2>/dev/null | head -n 1 || true)"
  KEY_PATH="$(ls -1t "${ROOT}"/config/dev-certs/*.key 2>/dev/null | head -n 1 || true)"
fi
[[ -n "$CERT_PATH" ]] || { echo "Missing cert in config/local/dev-certs/ (or legacy config/dev-certs/)" >&2; exit 2; }
[[ -n "$KEY_PATH" ]] || { echo "Missing key in config/local/dev-certs/ (or legacy config/dev-certs/)" >&2; exit 2; }

mkdir -p "$PID_DIR"
cp "$ROOT/config/server-linux.default.toml" "$RUNTIME_CONFIG"
rm -f "$RUNTIME_AUTH"

echo "[qf] root: ${ROOT}"
echo "[qf] ports: admin=${ADMIN_PORT} server=${SERVER_PORT}"

# Wait until a local TCP port actually accepts a connection.
#
# tmux `send-keys` only queues text into a pane, so this script previously printed
# started URLs while the build had not run and nothing was listening. Automation and
# operators then acted on a service that did not exist yet or never started at all.
# A timeout is reported as a distinct state rather than as success.
wait_for_port() {
  local host="$1" port="$2" label="$3" timeout_secs="${4:-120}"
  local waited=0
  while ((waited < timeout_secs)); do
    if nc -z "$host" "$port" 2>/dev/null; then
      echo "[qf] ready: ${label} on ${host}:${port} after ${waited}s"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "[qf] NOT READY: ${label} did not accept a connection on ${host}:${port} within ${timeout_secs}s" >&2
  echo "[qf]   inspect the build and process output with: tmux attach -t ${SESSION}" >&2
  return 1
}

if tmux has-session -t "${SESSION}" 2>/dev/null; then
  tmux kill-session -t "${SESSION}"
fi

tmux new-session -d -s "${SESSION}" -n "admin"

tmux send-keys -t "${SESSION}:admin" "cd \"${ROOT}\"" C-m
tmux send-keys -t "${SESSION}:admin" "cargo build -q" C-m
tmux send-keys -t "${SESSION}:admin" "bash scripts/build/build-web-admin.sh" C-m
tmux send-keys -t "${SESSION}:admin" "env QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1 RUST_LOG=info target/debug/quicfuscate server --listen 127.0.0.1:${SERVER_PORT} --cert \"${CERT_PATH}\" --key \"${KEY_PATH}\" --config \"${RUNTIME_CONFIG}\" --admin-web 127.0.0.1:${ADMIN_PORT} --admin-web-root assets/web-admin --admin-web-user admin --admin-web-password 123" C-m

echo "[qf] started tmux session: ${SESSION}; waiting for the admin UI to accept connections"

READINESS_FAILURES=0
wait_for_port 127.0.0.1 "${ADMIN_PORT}" "web admin UI" "${QF_READY_TIMEOUT_SECS:-240}" \
  || READINESS_FAILURES=$((READINESS_FAILURES + 1))

echo "[qf] web admin UI: http://127.0.0.1:${ADMIN_PORT}/ (login: admin / 123)"
echo "[qf] isolated admin auth store: ${RUNTIME_AUTH}"
echo "[qf] attach: tmux attach -t ${SESSION}"

if ((READINESS_FAILURES)); then
  echo "[qf] the admin UI is not reachable; the session is left running for inspection" >&2
  exit 1
fi
