#!/usr/bin/env bash
# Description: Test suite runner: test-e2e-admin-web.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
ADMIN_USER="admin"
ADMIN_PASS="E2E_TEST_ONLY_pw42"
ADMIN_ADDR="127.0.0.1:9000"
SERVER_ADDR="127.0.0.1:4433"
ADMIN_ADDR_SET=0
SERVER_ADDR_SET=0
ADMIN_WEB_ROOT="assets/web-admin"
REBUILD_WEB=0
USE_BINARY=""
CLIENT_BINARY="${QUICFUSCATE_E2E_RUNTIME_CLIENT_BINARY:-$PROJECT_ROOT/target/debug/quicfuscate}"
CERT_PATH=""
KEY_PATH=""
CA_PATH=""
READY_TIMEOUT_SECS=120
QKEY_TTL_SECS=120
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --admin-user) ADMIN_USER="$2"; shift;;
    --admin-pass) ADMIN_PASS="$2"; shift;;
    --admin-addr) ADMIN_ADDR="$2"; ADMIN_ADDR_SET=1; shift;;
    --server-addr) SERVER_ADDR="$2"; SERVER_ADDR_SET=1; shift;;
    --admin-web-root) ADMIN_WEB_ROOT="$2"; shift;;
    --rebuild-web) REBUILD_WEB=1;;
    --use-binary) USE_BINARY="$2"; shift;;
    --client-binary) CLIENT_BINARY="$2"; shift;;
    --cert) CERT_PATH="$2"; shift;;
    --key) KEY_PATH="$2"; shift;;
    --ca-file) CA_PATH="$2"; shift;;
    --ready-timeout) READY_TIMEOUT_SECS="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--admin-user USER] [--admin-pass PASS] [--admin-addr ADDR] [--server-addr ADDR] [--admin-web-root PATH] [--rebuild-web] [--use-binary PATH] [--client-binary PATH] [--cert PATH] [--key PATH] [--ca-file PATH] [--ready-timeout SECS] [--dry-run]"
      usage_common_flags
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "tests_e2e_admin_web"
JSON_FIRST_RUN=1

append_result() {
  local name="$1"; local result="$2"; local reason="$3"; local command_status="$4"
  local scope="${6:-e2e}"
  local command_argv_json="${7:-[]}"
  qf_json_append_object "$JSON" "name=$name" "result=$result" "reason=$reason" \
    "argv=json:$command_argv_json" "environment=json:$(qf_json_environment)" \
    "command_status=json:$command_status" "scope=$scope"
}

redacted_command_json() {
  local -a command=("$@")
  local index
  for ((index=1; index<${#command[@]}; index++)); do
    if [[ "${command[$((index - 1))]}" == "--admin-web-password" ]]; then
      command[index]="<redacted>"
    fi
  done
  qf_json_array "${command[@]}"
}

validate_endpoint() {
  local label="$1"; local value="$2"
  local port=""
  validate_control_free_value "$label" "$value" 256 || return 2
  if [[ "$value" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]+)$ ]]; then
    port="${BASH_REMATCH[2]}"
  elif [[ "$value" =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then
    port="${BASH_REMATCH[2]}"
  else
    error "${label} must be host:port or [ipv6]:port"
    return 2
  fi
  validate_nonnegative_int "${label} port" "$port" 65535
}

validate_credential() {
  local label="$1"; local value="$2"
  validate_control_free_value "$label" "$value" 256 || return 2
  [[ -n "$value" ]] || { error "${label} must not be empty"; return 2; }
}

validate_credential "admin username" "$ADMIN_USER"
validate_credential "admin password" "$ADMIN_PASS"
validate_endpoint "admin address" "$ADMIN_ADDR"
validate_endpoint "server address" "$SERVER_ADDR"
validate_positive_int "ready timeout" "$READY_TIMEOUT_SECS" 600
validate_positive_int "qkey TTL" "$QKEY_TTL_SECS" 3600
validate_control_free_value "admin web root" "$ADMIN_WEB_ROOT" 4096
validate_control_free_value "client binary path" "$CLIENT_BINARY" 4096
validate_control_free_value "use-binary path" "$USE_BINARY" 4096
validate_control_free_value "certificate path" "$CERT_PATH" 4096
validate_control_free_value "key path" "$KEY_PATH" 4096
validate_control_free_value "CA path" "$CA_PATH" 4096

if [[ "$DRY_RUN" -eq 1 ]]; then
  TMP_DIR="$OUTPUT_DIR/tmp"
  [[ -n "$CA_PATH" ]] || CA_PATH="$TMP_DIR/ca.crt"
  [[ -n "$CERT_PATH" ]] || CERT_PATH="$TMP_DIR/server.crt"
  [[ -n "$KEY_PATH" ]] || KEY_PATH="$TMP_DIR/server.key"
  SERVER_CMD=()
  if [[ -n "$USE_BINARY" ]]; then
    SERVER_CMD=(env RUST_LOG=info QUICFUSCATE_BRAIN=0 "$USE_BINARY")
  else
    SERVER_CMD=(env RUST_LOG=info QUICFUSCATE_BRAIN=0 cargo run --bin quicfuscate --)
  fi
  SERVER_CMD+=(
    server
    --listen "$SERVER_ADDR"
    --cert "$CERT_PATH"
    --key "$KEY_PATH"
    --front-domain cdn.cloudflare.com
    --admin-web "$ADMIN_ADDR"
    --admin-web-root "$ADMIN_WEB_ROOT"
    --admin-web-user "$ADMIN_USER"
    --admin-web-password "$ADMIN_PASS"
    --config "$TMP_DIR/server.toml"
  )
  REDACTED_SERVER_CMD=("${SERVER_CMD[@]}")
  for ((index=1; index<${#REDACTED_SERVER_CMD[@]}; index++)); do
    if [[ "${REDACTED_SERVER_CMD[$((index - 1))]}" == "--admin-web-password" ]]; then
      REDACTED_SERVER_CMD[index]="<redacted>"
    fi
  done
  redacted_command="$(printf '%q ' "${REDACTED_SERVER_CMD[@]}")"
  redacted_command="${redacted_command% }"
  info "DRY-RUN: planned admin E2E command"
  printf '%s\n' "$redacted_command"
  append_result "admin-e2e-plan" "SKIP" "dry_run" null "" "plan_only" \
    "$(redacted_command_json "${SERVER_CMD[@]}")"
  json_end "$JSON"
  exit 0
fi

require_cmd curl
require_cmd python3

print_system_banner
info "Admin Web E2E starting"

port_in_use() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
try:
    s.bind(("127.0.0.1", port))
except OSError:
    print("1")
else:
    print("0")
finally:
    s.close()
PY
}

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

if [[ "$SERVER_ADDR_SET" -eq 0 ]]; then
  NEW_PORT="$(pick_free_port)"
  SERVER_ADDR="127.0.0.1:${NEW_PORT}"
  info "Server port auto-selected: $SERVER_ADDR"
fi

if [[ "$ADMIN_ADDR_SET" -eq 0 ]]; then
  ADMIN_PORT="${ADMIN_ADDR##*:}"
  if [[ "$(port_in_use "$ADMIN_PORT")" == "1" ]]; then
    NEW_PORT="$(pick_free_port)"
    ADMIN_ADDR="127.0.0.1:${NEW_PORT}"
    info "Admin port in use, switched to $ADMIN_ADDR"
  fi
fi

TMP_DIR="$OUTPUT_DIR/tmp"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
if [[ "$(id -u)" -eq 0 ]] && getent passwd quicfuscate >/dev/null 2>&1; then
  chown quicfuscate:quicfuscate "$TMP_DIR"
fi
COOKIE_JAR="$TMP_DIR/cookies.txt"
CONFIG_FILE="$TMP_DIR/server.toml"
CONFIG_UPDATE="$TMP_DIR/server-update.toml"
PAYLOAD_FILE="$TMP_DIR/payload.json"
ORIGIN_HEADER="Origin: http://$ADMIN_ADDR"
CSRF_TOKEN=""

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "${DESKTOP_PID:-}" ]]; then
    kill "$DESKTOP_PID" 2>/dev/null || true
    wait "$DESKTOP_PID" 2>/dev/null || true
  fi
  if [[ -n "${CLIENT_PID:-}" ]]; then
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fetch_csrf_token() {
  local headers_file="$TMP_DIR/csrf.headers"
  curl -s -b "$COOKIE_JAR" -D "$headers_file" -o /dev/null "http://$ADMIN_ADDR/api/csrf" >/dev/null
  local code
  code="$(awk 'BEGIN{IGNORECASE=1}/^HTTP\//{c=$2}END{print c}' "$headers_file")"
  [[ "$code" == "200" ]] || die "Failed to fetch CSRF token (status $code)"
  CSRF_TOKEN="$(awk 'tolower($1)=="x-csrf-token:" {sub("\r$","",$2);print $2}' "$headers_file" | tail -n1)"
  [[ -n "$CSRF_TOKEN" ]] || die "Missing CSRF token header"
}

[[ -x "$CLIENT_BINARY" ]] || die "Missing QKey client binary: $CLIENT_BINARY"

if [[ -n "$CA_PATH" ]]; then
  [[ -n "$CERT_PATH" ]] || die "Missing server cert path. Provide --cert PATH with --ca-file PATH"
  [[ -n "$KEY_PATH" ]] || die "Missing server key path. Provide --key PATH with --ca-file PATH"
  [[ -s "$CA_PATH" ]] || die "Missing CA bundle: $CA_PATH"
else
  if [[ -n "$CERT_PATH" || -n "$KEY_PATH" ]]; then
    die "Custom --cert/--key requires a matching --ca-file; omit them to generate an ephemeral test PKI"
  fi
  require_cmd openssl
  CA_PATH="$TMP_DIR/ca.crt"
  CA_KEY_PATH="$TMP_DIR/ca.key"
  CERT_PATH="$TMP_DIR/server.crt"
  KEY_PATH="$TMP_DIR/server.key"
  SERVER_CSR_PATH="$TMP_DIR/server.csr"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -days 1 -subj '/CN=QuicFuscate Admin E2E CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$CA_KEY_PATH" -out "$CA_PATH" >/dev/null 2>&1
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:cdn.cloudflare.com,DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$KEY_PATH" -out "$SERVER_CSR_PATH" >/dev/null 2>&1
  openssl x509 -req -in "$SERVER_CSR_PATH" -CA "$CA_PATH" -CAkey "$CA_KEY_PATH" \
    -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$CERT_PATH" >/dev/null 2>&1
  chmod 600 "$CA_KEY_PATH" "$KEY_PATH"
  info "Generated ephemeral CA and server leaf for verified QKey TLS"
fi

cat > "$CONFIG_FILE" <<'TOML'
[fec]
mode = "auto"
initial_mode = "auto"
window_good = 20

[stealth]
mode = "auto"
enable_doh = true
enable_http3_masquerading = true
enable_domain_fronting = false

[optimization]
memory_pool_size = 33554432
TOML

cat > "$CONFIG_UPDATE" <<'TOML'
[fec]
mode = "auto"
initial_mode = "auto"
window_good = 20

[stealth]
mode = "auto"
enable_doh = true
enable_http3_masquerading = true
enable_domain_fronting = false

[optimization]
memory_pool_size = 16777216
TOML

if [[ "$REBUILD_WEB" -eq 1 || ! -f "$ADMIN_WEB_ROOT/index.html" ]]; then
  info "Building web-admin assets"
  run "$PROJECT_ROOT/scripts/build/build-web-admin.sh"
fi

if [[ ! -f "$ADMIN_WEB_ROOT/index.html" ]]; then
  die "Missing web-admin assets at $ADMIN_WEB_ROOT/index.html"
fi

info "Starting server (listen: $SERVER_ADDR, admin: $ADMIN_ADDR)"
SERVER_CMD=()
if [[ -n "$USE_BINARY" ]]; then
  SERVER_CMD=("env" "RUST_LOG=info" "QUICFUSCATE_BRAIN=0" "$USE_BINARY")
else
  SERVER_CMD=("env" "RUST_LOG=info" "QUICFUSCATE_BRAIN=0" "cargo" "run" "--bin" "quicfuscate" "--")
fi
SERVER_CMD+=(
  "server"
  "--listen" "$SERVER_ADDR"
  "--cert" "$CERT_PATH"
  "--key" "$KEY_PATH"
  "--front-domain" "cdn.cloudflare.com"
  "--admin-web" "$ADMIN_ADDR"
  "--admin-web-root" "$ADMIN_WEB_ROOT"
  "--admin-web-user" "$ADMIN_USER"
  "--admin-web-password" "$ADMIN_PASS"
  "--config" "$CONFIG_FILE"
)

SERVER_LOG="$OUTPUT_DIR/server.log"
if [[ -n "${DRY_RUN:-}" ]]; then
  echo "DRY-RUN: ${SERVER_CMD[*]}"
else
  "${SERVER_CMD[@]}" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
fi

info "Waiting for admin web to become ready"
READY=0
READY_STEPS=$((READY_TIMEOUT_SECS * 4))
for _ in $(seq 1 "$READY_STEPS"); do
  if [[ -n "${SERVER_PID:-}" ]]; then
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      error "Server process exited early"
      if [[ -f "$SERVER_LOG" ]]; then
        tail -n 200 "$SERVER_LOG" || true
      fi
      exit 1
    fi
  fi
  code="$(curl -s -o /dev/null -w "%{http_code}" "http://$ADMIN_ADDR/")" || true
  if [[ "$code" == "200" ]]; then
    READY=1
    break
  fi
  sleep 0.25
done
[[ "$READY" -eq 1 ]] || die "Admin web did not become ready at http://$ADMIN_ADDR/"

info "Checking static index"
INDEX_BODY="$(curl -s "http://$ADMIN_ADDR/")"
python3 - "$INDEX_BODY" <<'PY'
import sys
body = sys.argv[1]
if "<html" not in body.lower():
    raise SystemExit("index.html response missing html tag")
PY

info "Ensuring unauthorized requests are rejected"
code="$(curl -s -o /dev/null -w "%{http_code}" "http://$ADMIN_ADDR/api/status")"
[[ "$code" == "401" ]] || die "Expected 401 for unauthorized status, got $code"

info "Logging in"
LOGIN_PAYLOAD="$(python3 - "$ADMIN_USER" "$ADMIN_PASS" <<'PY'
import json, sys
print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
)"
LOGIN_RESP="$(curl -s -c "$COOKIE_JAR" -H "Content-Type: application/json" -d "$LOGIN_PAYLOAD" "http://$ADMIN_ADDR/api/login")"
python3 - "$LOGIN_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("login failed")
PY
fetch_csrf_token

info "Fetching admin auth status"
AUTH_STATUS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/admin/auth")"
python3 - "$AUTH_STATUS_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("admin auth status failed")
data = resp.get("data") or {}
if "user" not in data:
    raise SystemExit("admin auth status missing user")
if "requires_password_change" not in data:
    raise SystemExit("admin auth status missing requires_password_change")
PY

info "Updating admin password (forces re-login)"
NEW_ADMIN_PASS="pw-${RANDOM}${RANDOM}"
AUTH_UPDATE_PAYLOAD="$(python3 - "$ADMIN_USER" "$ADMIN_PASS" "$NEW_ADMIN_PASS" <<'PY'
import json, sys
print(json.dumps({"new_username": sys.argv[1], "current_password": sys.argv[2], "new_password": sys.argv[3]}))
PY
)"
AUTH_UPDATE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$AUTH_UPDATE_PAYLOAD" "http://$ADMIN_ADDR/api/admin/auth")"
python3 - "$AUTH_UPDATE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"admin auth update failed: {resp}")
PY

code="$(curl -s -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "http://$ADMIN_ADDR/api/status")"
[[ "$code" == "401" ]] || die "Expected 401 after credential update, got $code"

ADMIN_PASS="$NEW_ADMIN_PASS"
LOGIN_PAYLOAD="$(python3 - "$ADMIN_USER" "$ADMIN_PASS" <<'PY'
import json, sys
print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}))
PY
)"
LOGIN_RESP="$(curl -s -c "$COOKIE_JAR" -H "Content-Type: application/json" -d "$LOGIN_PAYLOAD" "http://$ADMIN_ADDR/api/login")"
python3 - "$LOGIN_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("re-login failed after admin credential update")
PY
fetch_csrf_token

info "Fetching status"
STATUS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/status")"
python3 - "$STATUS_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("status failed")
data = resp.get("data") or {}
for key in ("version", "uptime_secs", "clients_active"):
    if key not in data:
        raise SystemExit(f"status missing {key}")
PY

info "Listing clients"
CLIENTS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/clients")"
python3 - "$CLIENTS_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("clients failed")
PY

info "Requesting metrics"
METRICS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/metrics")"
python3 - "$METRICS_RESP" <<'PY'
import sys
body = sys.argv[1]
if "quicfuscate_up" not in body:
    raise SystemExit("metrics missing quicfuscate_up")
PY

info "Reading config"
CONFIG_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/config")"
python3 - "$CONFIG_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("config read failed")
data = resp.get("data") or {}
if "config" not in data:
    raise SystemExit("config response missing config field")
PY

info "Generating QKey"
QKEY_PAYLOAD="$(python3 - "$QKEY_TTL_SECS" <<'PY'
import json, sys
print(json.dumps({"ttl_seconds": int(sys.argv[1])}))
PY
)"
QKEY_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$QKEY_PAYLOAD" "http://$ADMIN_ADDR/api/qkey")"
QKEY_INFO="$(python3 - "$QKEY_RESP" "$QKEY_TTL_SECS" <<'PY'
import json, sys, time
resp = json.loads(sys.argv[1])
ttl = int(sys.argv[2])
if not resp.get("success"):
    raise SystemExit(f"qkey generation failed: {resp}")
data = resp.get("data") or {}
qkey = data.get("qkey", "")
expires_at = data.get("expires_at")
if not qkey.startswith("QKey-"):
    raise SystemExit(f"invalid qkey prefix: {resp}")
if expires_at is None:
    raise SystemExit(f"qkey expires_at missing: {resp}")
now = int(time.time())
min_expected = now + max(ttl - 30, 0)
max_expected = now + ttl + 90
if not (min_expected <= int(expires_at) <= max_expected):
    raise SystemExit("qkey expires_at out of expected range")
print(qkey)
print(expires_at)
PY
)"
mapfile -t QKEY_LINES <<< "$QKEY_INFO"
QKEY_VALUE="${QKEY_LINES[0]:-}"
QKEY_EXPIRES_AT="${QKEY_LINES[1]:-}"
[[ -n "$QKEY_VALUE" ]] || die "Missing qkey value"
[[ -n "$QKEY_EXPIRES_AT" ]] || die "Missing qkey expires_at"

info "Connecting with the runtime QKey client and retaining an authenticated session"
CLIENT_LOG="$OUTPUT_DIR/qkey-revocation-client.log"
AUTH_SUCCEEDED_BEFORE="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/metrics" \
  | awk '$1 == "quicfuscate_auth_succeeded_total" {print $2; exit}')"
[[ "$AUTH_SUCCEEDED_BEFORE" =~ ^[0-9]+$ ]] || die "Could not read baseline QKey auth metric"
"$CLIENT_BINARY" client \
  --remote "$SERVER_ADDR" \
  --url "https://cdn.cloudflare.com/qf-e2e-probe" \
  --qkey "$QKEY_VALUE" \
  --ca-file "$CA_PATH" \
  --no-utls \
  --verify-peer \
  --disable-doh \
  --disable-fronting >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
CLIENT_CONNECTED=0
for _ in $(seq 1 100); do
  AUTH_SUCCEEDED_NOW="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/metrics" \
    | awk '$1 == "quicfuscate_auth_succeeded_total" {print $2; exit}')"
  if [[ "$AUTH_SUCCEEDED_NOW" =~ ^[0-9]+$ ]] \
    && (( AUTH_SUCCEEDED_NOW > AUTH_SUCCEEDED_BEFORE )); then
    CLIENT_CONNECTED=1
    break
  fi
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    tail -n 100 "$CLIENT_LOG" >&2 || true
    die "QKey client exited before active-session proof"
  fi
  sleep 0.1
done
[[ "$CLIENT_CONNECTED" -eq 1 ]] || die "Runtime QKey client did not authenticate before revocation"

info "Updating config while the authenticated QKey session is active"
python3 - "$CONFIG_UPDATE" > "$PAYLOAD_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r") as fh:
    text = fh.read()
print(json.dumps({"config": text}))
PY
UPDATE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d @"$PAYLOAD_FILE" "http://$ADMIN_ADDR/api/config")"
python3 - "$UPDATE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"config update failed: {resp}")
PY

info "Connecting with QKey (desktop engine)"
info "Desktop runtime transport-connect validation is covered in dedicated integration suites."

info "Listing QKeys"
QKEYS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/qkeys")"
QKEY_ID="$(python3 - "$QKEYS_RESP" "$QKEY_VALUE" "$QKEY_EXPIRES_AT" <<'PY'
import json, sys
import hashlib
resp = json.loads(sys.argv[1])
qkey_value = sys.argv[2]
expected_expires = sys.argv[3]
if not resp.get("success"):
    raise SystemExit("qkeys list failed")
keys = (resp.get("data") or {}).get("keys") or []

trimmed = qkey_value.strip()
prefix = "QKey-"
if trimmed[:len(prefix)].lower() == prefix.lower():
    rest = trimmed[len(prefix):]
    canonical = trimmed if trimmed.startswith(prefix) else f"{prefix}{rest}"
else:
    canonical = trimmed
expected_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]

for entry in keys:
    if entry.get("id") == expected_id:
        if str(entry.get("expires_at")) != str(expected_expires):
            raise SystemExit("qkey expires_at mismatch")
        print(expected_id)
        raise SystemExit(0)
raise SystemExit("generated qkey id not found in list")
PY
)"
[[ -n "$QKEY_ID" ]] || die "Missing qkey id"

info "Revoking QKey"
REVOKE_PAYLOAD="$(python3 - "$QKEY_ID" <<'PY'
import json, sys
print(json.dumps({"id": sys.argv[1]}))
PY
)"
REVOKE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$REVOKE_PAYLOAD" "http://$ADMIN_ADDR/api/qkeys/revoke")"
python3 - "$REVOKE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"qkey revoke failed: {resp}")
PY

info "Verifying revoked QKey is rejected"
QKEYS_AFTER_REVOKE_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/qkeys")"
python3 - "$QKEYS_AFTER_REVOKE_RESP" "$QKEY_ID" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
qid = sys.argv[2]
if not resp.get("success"):
    raise SystemExit("qkeys list failed after revoke")
keys = (resp.get("data") or {}).get("keys") or []
entry = next((k for k in keys if k.get("id") == qid), None)
if entry is None:
    raise SystemExit(0)
is_revoked = bool(entry.get("revoked")) or bool(entry.get("disabled")) or bool(entry.get("is_revoked"))
if not is_revoked:
    raise SystemExit("revoked qkey not marked revoked/disabled in list")
PY

info "Verifying immediate active-session closure and zero stale clients"
CLIENT_EXIT=0
for _ in $(seq 1 100); do
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$CLIENT_PID" 2>/dev/null; then
  kill -TERM "$CLIENT_PID" 2>/dev/null || true
fi
if wait "$CLIENT_PID"; then
  CLIENT_EXIT=0
else
  CLIENT_EXIT=$?
fi
CLIENT_PID=""
[[ "$CLIENT_EXIT" -ne 0 ]] || die "revoked active QKey client remained connected"
grep -F 'VPN server closed the connection' "$CLIENT_LOG" >/dev/null \
  || die "revoked active QKey client did not report immediate closure"

CLIENTS_AFTER_REVOKE_RESP=""
for _ in $(seq 1 100); do
  CLIENTS_AFTER_REVOKE_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/clients")"
  if python3 - "$CLIENTS_AFTER_REVOKE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(1)
clients = resp.get("data")
if clients == []:
    raise SystemExit(0)
raise SystemExit(1)
PY
  then
    break
  fi
  sleep 0.1
done
python3 - "$CLIENTS_AFTER_REVOKE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
clients = resp.get("data")
if clients != []:
    raise SystemExit(f"stale active client remains after revoke: {clients}")
PY

info "Fetching logs (normal mode)"
LOGS_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/logs?cursor=0")"
python3 - "$LOGS_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("logs fetch failed")
data = resp.get("data") or {}
lines = data.get("lines") or []
if not isinstance(lines, list) or len(lines) < 1:
    raise SystemExit("expected non-empty logs in normal mode")
msgs = " ".join([(l.get("msg") or "") for l in lines if isinstance(l, dict)])
if "admin action=" not in msgs and "Server listening" not in msgs:
    raise SystemExit("expected at least one recognizable log line")
PY

info "Switching logging mode to minimal (redaction)"
LOG_MODE_PAYLOAD='{"mode":"minimal"}'
MODE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$LOG_MODE_PAYLOAD" "http://$ADMIN_ADDR/api/config/logging")"
python3 - "$MODE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"failed to set logging mode minimal: {resp}")
PY

LOGS_MIN_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/logs?cursor=0")"
python3 - "$LOGS_MIN_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("logs fetch failed (minimal)")
data = resp.get("data") or {}
lines = data.get("lines") or []
msgs = " ".join([(l.get("msg") or "") for l in lines if isinstance(l, dict)])
if "127.0.0.1" in msgs:
    raise SystemExit("minimal mode should redact ipv4 strings")
if "<ip>" not in msgs:
    raise SystemExit("minimal mode should include <ip> redaction marker when ipv4 present")
PY

info "Switching logging mode to no-log (buffer cleared)"
LOG_MODE_PAYLOAD='{"mode":"no-log"}'
MODE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$LOG_MODE_PAYLOAD" "http://$ADMIN_ADDR/api/config/logging")"
python3 - "$MODE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"failed to set logging mode no-log: {resp}")
PY

LOGS_NOLOG_RESP="$(curl -s -b "$COOKIE_JAR" "http://$ADMIN_ADDR/api/logs?cursor=0")"
python3 - "$LOGS_NOLOG_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit("logs fetch failed (no-log)")
data = resp.get("data") or {}
lines = data.get("lines") or []
cursor = data.get("cursor")
if lines not in ([], None) and len(lines) != 0:
    raise SystemExit("no-log should return empty logs")
if cursor not in (0, None):
    raise SystemExit("no-log should reset cursor to 0")
PY

info "Restoring logging mode to normal"
LOG_MODE_PAYLOAD='{"mode":"normal"}'
MODE_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d "$LOG_MODE_PAYLOAD" "http://$ADMIN_ADDR/api/config/logging")"
python3 - "$MODE_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"failed to restore logging mode normal: {resp}")
PY

info "Logging out"
LOGOUT_RESP="$(curl -s -b "$COOKIE_JAR" -H "Content-Type: application/json" -H "$ORIGIN_HEADER" -H "X-CSRF-Token: $CSRF_TOKEN" -d '{}' "http://$ADMIN_ADDR/api/logout")"
python3 - "$LOGOUT_RESP" <<'PY'
import json, sys
resp = json.loads(sys.argv[1])
if not resp.get("success"):
    raise SystemExit(f"logout failed: {resp}")
PY

info "Verifying logout"
code="$(curl -s -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "http://$ADMIN_ADDR/api/status")"
[[ "$code" == "401" ]] || die "Expected 401 after logout, got $code"

info "Admin Web E2E completed"
append_result "admin-e2e" "PASS" "" 0 "" "live" "$(redacted_command_json "${SERVER_CMD[@]}")"
json_end "$JSON"
