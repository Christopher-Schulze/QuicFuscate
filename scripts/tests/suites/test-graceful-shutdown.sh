#!/usr/bin/env bash
# Description: Live-process proof for graceful reload, drain, rejection, and close flushing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

BINARY="${QUICFUSCATE_TEST_BINARY:-$PROJECT_ROOT/target/debug/quicfuscate}"
TEMP_ROOT="${TMPDIR:-/tmp}"
TEMP_ROOT="${TEMP_ROOT%/}"
PROOF_DIR="$(mktemp -d "$TEMP_ROOT/quicfuscate-todo448.XXXXXX")"
SERVER_PID=""
CLIENT_A_PID=""
CLIENT_B_PID=""

process_running() {
  local pid="$1"
  local state
  state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ' || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

stop_process() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  if process_running "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
      process_running "$pid" || break
      sleep 0.1
    done
  fi
  if process_running "$pid"; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  stop_process "$CLIENT_B_PID"
  stop_process "$CLIENT_A_PID"
  stop_process "$SERVER_PID"
  case "$PROOF_DIR" in
    "$TEMP_ROOT"/quicfuscate-todo448.*)
      find "$PROOF_DIR" -depth -type f -delete 2>/dev/null || true
      find "$PROOF_DIR" -depth -type d -exec rmdir {} \; 2>/dev/null || true
      ;;
  esac
}
trap cleanup EXIT

report_error() {
  local exit_code="$?"
  local line="$1"
  printf 'FAIL: graceful-shutdown harness stopped at line %s with exit %s\n' "$line" "$exit_code" >&2
}
trap 'report_error "$LINENO"' ERR

free_tcp_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

free_udp_port() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

wait_for_log() {
  local file="$1"
  local pattern="$2"
  local pid="$3"
  local attempts="$4"
  for _ in $(seq 1 "$attempts"); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    process_running "$pid" || return 1
    sleep 0.1
  done
  return 1
}

wait_for_process_exit() {
  local pid="$1"
  local attempts="$2"
  for _ in $(seq 1 "$attempts"); do
    process_running "$pid" || return 0
    sleep 0.1
  done
  return 1
}

[[ -x "$BINARY" ]] || {
  echo "FAIL: missing executable $BINARY" >&2
  exit 1
}
command -v curl >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null

SERVER_PORT="$(free_udp_port)"
ADMIN_PORT="$(free_tcp_port)"
CA_CERT="$PROOF_DIR/ca.crt"
CA_KEY="$PROOF_DIR/ca.key"
SERVER_CERT="$PROOF_DIR/server.crt"
SERVER_KEY="$PROOF_DIR/server.key"
SERVER_CSR="$PROOF_DIR/server.csr"
CONFIG="$PROOF_DIR/server.toml"
SERVER_LOG="$PROOF_DIR/server.log"
CLIENT_A_LOG="$PROOF_DIR/client-a.log"
CLIENT_B_LOG="$PROOF_DIR/client-b.log"
COOKIE_JAR="$PROOF_DIR/cookies"
AUDIT_LOG="$PROOF_DIR/audit.ndjson"
ADMIN_USER="proof-admin"
ADMIN_PASSWORD="ProofOnly_448_Strong_29"

cp config/quicfuscate.toml "$CONFIG"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -days 1 -subj '/CN=QuicFuscate TODO-448 Proof CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$CA_KEY" -out "$CA_CERT" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -subj '/CN=cloudflare-dns.com' \
  -addext 'subjectAltName=DNS:cloudflare-dns.com,DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$SERVER_KEY" -out "$SERVER_CSR" >/dev/null 2>&1
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$SERVER_CERT" >/dev/null 2>&1
chmod 600 "$CA_KEY" "$SERVER_KEY"

QUICFUSCATE_ENABLE_ADMIN_SHUTDOWN=1 RUST_LOG=info QUICFUSCATE_BRAIN=0 "$BINARY" server \
  --listen "127.0.0.1:$SERVER_PORT" \
  --cert "$SERVER_CERT" \
  --key "$SERVER_KEY" \
  --front-domain cloudflare-dns.com \
  --admin-web "127.0.0.1:$ADMIN_PORT" \
  --admin-web-root assets/web-admin \
  --admin-web-user "$ADMIN_USER" \
  --admin-web-password "$ADMIN_PASSWORD" \
  --qkey-store "$PROOF_DIR/qkeys.json" \
  --audit-log "$AUDIT_LOG" \
  --config "$CONFIG" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

ADMIN_READY=0
for _ in $(seq 1 150); do
  process_running "$SERVER_PID" || break
  STATUS_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ADMIN_PORT/api/health" 2>/dev/null || true)"
  if [[ "$STATUS_CODE" == "200" ]]; then
    ADMIN_READY=1
    break
  fi
  sleep 0.1
done
[[ "$ADMIN_READY" -eq 1 ]] || {
  tail -n 120 "$SERVER_LOG" >&2
  echo "FAIL: admin endpoint did not become ready" >&2
  exit 1
}

curl -sS -c "$COOKIE_JAR" -H 'Content-Type: application/json' \
  --data-binary '{"username":"proof-admin","password":"ProofOnly_448_Strong_29"}' \
  "http://127.0.0.1:$ADMIN_PORT/api/login" >"$PROOF_DIR/login.json"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["success"]' "$PROOF_DIR/login.json"

curl -sS -b "$COOKIE_JAR" -D "$PROOF_DIR/csrf.headers" -o /dev/null \
  "http://127.0.0.1:$ADMIN_PORT/api/csrf"
CSRF_TOKEN="$(awk 'tolower($1)=="x-csrf-token:" {sub("\r$", "", $2); print $2}' "$PROOF_DIR/csrf.headers" | tail -n1)"
[[ -n "$CSRF_TOKEN" ]] || {
  echo "FAIL: missing CSRF token" >&2
  exit 1
}

curl -sS -b "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -H "Origin: http://127.0.0.1:$ADMIN_PORT" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  --data-binary '{"ttl_seconds":120}' \
  "http://127.0.0.1:$ADMIN_PORT/api/qkey" >"$PROOF_DIR/qkey-response.json"
QKEY="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["success"]; print(d["data"]["qkey"])' "$PROOF_DIR/qkey-response.json")"
[[ "$QKEY" == QKey-* ]] || {
  echo "FAIL: invalid QKey response" >&2
  exit 1
}

start_client() {
  local log_file="$1"
  "$BINARY" client \
    --remote "127.0.0.1:$SERVER_PORT" \
    --url 'https://cloudflare-dns.com/' \
    --qkey "$QKEY" \
    --ca-file "$CA_CERT" \
    --verify-peer \
    --no-utls \
    --config "$CONFIG" >"$log_file" 2>&1 &
  STARTED_PID=$!
}

start_client "$CLIENT_A_LOG"
CLIENT_A_PID=$STARTED_PID
start_client "$CLIENT_B_LOG"
CLIENT_B_PID=$STARTED_PID
wait_for_log "$CLIENT_A_LOG" 'TLS handshake complete' "$CLIENT_A_PID" 200
wait_for_log "$CLIENT_B_LOG" 'TLS handshake complete' "$CLIENT_B_PID" 200

curl -sS -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/status" >"$PROOF_DIR/status-before.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; assert d["clients_active"] == 2, d' "$PROOF_DIR/status-before.json"

kill -HUP "$SERVER_PID"
wait_for_log "$SERVER_LOG" 'Configuration reloaded successfully (SIGHUP): scope=NextConnectionOnly, active_sessions_unchanged=2' "$SERVER_PID" 100
curl -sS -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/drain/status" >"$PROOF_DIR/drain-before.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; assert d == {"state":"running","active_connections":2,"grace_period_ms":5000,"drain_elapsed_ms":0}, d' "$PROOF_DIR/drain-before.json"

DRAIN_STARTED_NS="$(python3 -c 'import time; print(time.monotonic_ns())')"
curl -sS -b "$COOKIE_JAR" -H 'Content-Type: application/json' \
  -H "Origin: http://127.0.0.1:$ADMIN_PORT" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  --data-binary '{}' "http://127.0.0.1:$ADMIN_PORT/api/drain" >"$PROOF_DIR/drain-response.json"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["success"]' "$PROOF_DIR/drain-response.json"
curl -sS -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/drain/status" >"$PROOF_DIR/drain-active.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; assert d["state"] == "draining" and d["active_connections"] == 2 and d["grace_period_ms"] == 5000, d' "$PROOF_DIR/drain-active.json"

python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",0)); s.sendto(b"new-connection-attempt",("127.0.0.1",int(sys.argv[1]))); s.close()' "$SERVER_PORT"
sleep 0.2
curl -sS -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/status" >"$PROOF_DIR/status-after-reject.json"
python3 -c 'import json,sys; a=json.load(open(sys.argv[1]))["data"]; b=json.load(open(sys.argv[2]))["data"]; assert b["clients_active"] == 2, b; assert b["connections_rejected"] == a["connections_rejected"] + 1, (a,b)' "$PROOF_DIR/status-before.json" "$PROOF_DIR/status-after-reject.json"

kill -TERM "$CLIENT_A_PID"
wait "$CLIENT_A_PID"
CLIENT_A_PID=""
CLIENT_CLOSED=0
for _ in $(seq 1 80); do
  curl -sS -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/drain/status" >"$PROOF_DIR/drain-after-client-close.json" 2>/dev/null || true
  ACTIVE_CONNECTIONS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("data",{}).get("active_connections",-1))' "$PROOF_DIR/drain-after-client-close.json" 2>/dev/null || true)"
  if [[ "$ACTIVE_CONNECTIONS" == "1" ]]; then
    CLIENT_CLOSED=1
    break
  fi
  sleep 0.05
done
[[ "$CLIENT_CLOSED" -eq 1 ]] || {
  echo "FAIL: client close was not reconciled during drain" >&2
  exit 1
}

wait_for_process_exit "$SERVER_PID" 80 || {
  tail -n 120 "$SERVER_LOG" >&2
  echo "FAIL: server did not exit after drain deadline" >&2
  exit 1
}
wait "$SERVER_PID"
SERVER_PID=""
DRAIN_ENDED_NS="$(python3 -c 'import time; print(time.monotonic_ns())')"
DRAIN_ELAPSED_MS="$(( (DRAIN_ENDED_NS - DRAIN_STARTED_NS) / 1000000 ))"
[[ "$DRAIN_ELAPSED_MS" -ge 4900 && "$DRAIN_ELAPSED_MS" -lt 7000 ]] || {
  echo "FAIL: drain elapsed ${DRAIN_ELAPSED_MS}ms outside [4900,7000)" >&2
  exit 1
}

wait_for_process_exit "$CLIENT_B_PID" 30 || {
  echo "FAIL: remaining client did not exit after the server close frame" >&2
  exit 1
}
if wait "$CLIENT_B_PID"; then
  CLIENT_B_EXIT=0
else
  CLIENT_B_EXIT=$?
fi
CLIENT_B_PID=""
[[ "$CLIENT_B_EXIT" -eq 1 ]] || {
  echo "FAIL: remaining client exited with $CLIENT_B_EXIT instead of fail-closed status 1" >&2
  exit 1
}
grep -q 'VPN server closed the connection; firewall remains fail-closed' "$CLIENT_B_LOG"

grep -q 'Server drain started (reason=admin_drain, grace_ms=5000)' "$SERVER_LOG"
grep -q 'Server drain complete (active_clients=1' "$SERVER_LOG"
grep -q 'Server stopped' "$SERVER_LOG"
if grep -q 'Failed to flush shutdown frame\|Final shutdown frame flush exceeded' "$SERVER_LOG"; then
  echo "FAIL: server shutdown frame flush failed" >&2
  exit 1
fi
if grep -q 'Client shutdown frame flush failed' "$CLIENT_A_LOG"; then
  echo "FAIL: client shutdown frame flush failed" >&2
  exit 1
fi

"$BINARY" verify-audit-log "$AUDIT_LOG" >"$PROOF_DIR/audit-verify.log"
python3 -c 'import json,sys; events=[json.loads(line)["event"] for line in open(sys.argv[1]) if line.strip()]; required={"client_authenticated":2,"admin_action":1,"config_reloaded":1,"connection_established":2,"connection_closed":1}; missing={event:minimum for event,minimum in required.items() if events.count(event)<minimum}; assert not missing,(missing,events)' "$AUDIT_LOG"
grep -q 'SIGHUP triggered next-connection-only config reload; 2 active sessions unchanged' "$AUDIT_LOG"

printf 'PASS: authenticated_clients=2 reload=SIGHUP scope=next-connection-only active_sessions_unchanged=2 drain=running-to-draining-to-stopped rejected_new_connection=1 client_close=2-to-1 grace_ms=5000 elapsed_ms=%s close_flush=clean audit_chain=valid\n' "$DRAIN_ELAPSED_MS"
