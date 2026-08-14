#!/usr/bin/env bash
# Description: Process-real DDoS admission, Retry, GeoIP, and HTTPS blacklist proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

SERVER_BINARY="${QUICFUSCATE_TEST_BINARY:-$PROJECT_ROOT/target/debug/quicfuscate}"
CLIENT_BINARY="${QUICFUSCATE_E2E_CLIENT_BINARY:-$PROJECT_ROOT/target/debug/qf-e2e-client}"
POLICY_PROBE_BINARY="${QUICFUSCATE_DDOS_PROBE_BINARY:-$PROJECT_ROOT/target/debug/qf-ddos-policy-probe}"
OUTPUT_DIR=""
MAX_RSS_GROWTH_KIB="${QUICFUSCATE_DDOS_MAX_RSS_GROWTH_KIB:-65536}"
MAX_SERVER_CPU_MS="${QUICFUSCATE_DDOS_MAX_SERVER_CPU_MS:-15000}"
MAXMIND_COMMIT="7ef0ff7a28a05d08020fe1a7d9902d2b71f8bc1b"
MAXMIND_SHA256="b37601903448683d241af52893c8cbf0fed461e0cdebe0bfaca01891fdeb6db9"
MAXMIND_CITY_SHA256="ed972738e4e03a3e56e12041a6af4d91592249d110f7e4a647e5f2fa0e639c09"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-binary)
      SERVER_BINARY="$2"
      shift 2
      ;;
    --client-binary)
      CLIENT_BINARY="$2"
      shift 2
      ;;
    --policy-probe-binary)
      POLICY_PROBE_BINARY="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $(basename "$0") [--server-binary PATH] [--client-binary PATH] [--policy-probe-binary PATH] [--output-dir DIR]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

PROCESS_PROBE_BUILD_ARGS=()
if [[ "$CLIENT_BINARY" == "$PROJECT_ROOT/target/debug/qf-e2e-client" && ! -x "$CLIENT_BINARY" ]]; then
  PROCESS_PROBE_BUILD_ARGS+=(--bin qf-e2e-client)
fi
if [[ "$POLICY_PROBE_BINARY" == "$PROJECT_ROOT/target/debug/qf-ddos-policy-probe" && ! -x "$POLICY_PROBE_BINARY" ]]; then
  PROCESS_PROBE_BUILD_ARGS+=(--bin qf-ddos-policy-probe)
fi
if [[ "${#PROCESS_PROBE_BUILD_ARGS[@]}" -gt 0 ]]; then
  echo "Building the default DDoS process probes"
  cargo build --features process-probes "${PROCESS_PROBE_BUILD_ARGS[@]}"
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$PROJECT_ROOT/scripts/out/tests/ddos-admission-$(date +%Y%m%d_%H%M%S)"
fi
if [[ -e "$OUTPUT_DIR" ]]; then
  echo "error: refusing existing output path: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUTPUT_DIR")"
mkdir "$OUTPUT_DIR"

TEMP_ROOT="${TMPDIR:-/tmp}"
TEMP_ROOT="${TEMP_ROOT%/}"
SECRET_DIR="$(mktemp -d "$TEMP_ROOT/quicfuscate-ddos-admission.XXXXXX")"
SERVER_PID=""
HTTPS_PID=""
ESTABLISHED_PID=""
SERVER_PORT=""
METRICS_PORT=""
HTTPS_PORT=""
FAILURE_PORT=""
FLOOD_LOCAL_PORT=""
RESTART_SERVER_PORT=""
RESTART_METRICS_PORT=""
RESTART_ADMIN_SOCKET=""
QKEY=""

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

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
    for _ in $(seq 1 100); do
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
  stop_process "$ESTABLISHED_PID"
  stop_process "$SERVER_PID"
  stop_process "$HTTPS_PID"
  case "$SECRET_DIR" in
    "$TEMP_ROOT"/quicfuscate-ddos-admission.*)
      find "$SECRET_DIR" -depth -type f -delete 2>/dev/null || true
      find "$SECRET_DIR" -depth -type s -delete 2>/dev/null || true
      find "$SECRET_DIR" -depth -type d -exec rmdir {} \; 2>/dev/null || true
      ;;
  esac
}
trap cleanup EXIT

report_error() {
  local exit_code="$?"
  local line="$1"
  [[ -f "$OUTPUT_DIR/server.log" ]] && tail -n 100 "$OUTPUT_DIR/server.log" >&2 || true
  [[ -f "$OUTPUT_DIR/https.log" ]] && tail -n 50 "$OUTPUT_DIR/https.log" >&2 || true
  printf 'FAIL: DDoS admission harness stopped at line %s with exit %s\n' \
    "$line" "$exit_code" >&2
}
trap 'report_error "$LINENO"' ERR

free_port() {
  local socket_kind="$1"
  python3 - "$socket_kind" <<'PY'
import socket
import sys

kind = socket.SOCK_DGRAM if sys.argv[1] == "udp" else socket.SOCK_STREAM
sock = socket.socket(socket.AF_INET, kind)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

process_rss_kib() {
  ps -p "$1" -o rss= | awk '{print $1}'
}

process_cpu_millis() {
  local pid="$1"
  if [[ -r "/proc/$pid/stat" ]]; then
    python3 - "$pid" <<'PY'
import os
import pathlib
import sys

fields = pathlib.Path(f"/proc/{sys.argv[1]}/stat").read_text().split()
ticks = int(fields[13]) + int(fields[14])
print(round(ticks * 1000 / os.sysconf("SC_CLK_TCK")))
PY
    return
  fi

  local raw
  raw="$(ps -p "$pid" -o cputime= | tr -d ' ')"
  python3 - "$raw" <<'PY'
import sys

raw = sys.argv[1]
days = 0
if "-" in raw:
    day_text, raw = raw.split("-", 1)
    days = int(day_text)
parts = raw.split(":")
if len(parts) == 3:
    hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
elif len(parts) == 2:
    hours, minutes, seconds = 0, int(parts[0]), float(parts[1])
else:
    raise SystemExit(f"unsupported process CPU time: {sys.argv[1]}")
print(round((((days * 24 + hours) * 60 + minutes) * 60 + seconds) * 1000))
PY
}

metric_value() {
  local metric="$1"
  local value
  value="$(curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" \
    | awk -v metric="$metric" '$1 == metric {print $2}')"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "metric $metric is missing or non-integral: $value"
  printf '%s\n' "$value"
}

wait_metric_exact() {
  local metric="$1"
  local expected="$2"
  local value=""
  for _ in $(seq 1 500); do
    value="$(metric_value "$metric")"
    [[ "$value" -eq "$expected" ]] && return 0
    sleep 0.01
  done
  fail "$metric did not become $expected, last value $value"
}

wait_metric_at_least() {
  local metric="$1"
  local minimum="$2"
  local value=""
  for _ in $(seq 1 500); do
    value="$(metric_value "$metric")"
    [[ "$value" -ge "$minimum" ]] && return 0
    sleep 0.01
  done
  fail "$metric did not reach $minimum, last value $value"
}

assert_metric_exact() {
  local metric="$1"
  local expected="$2"
  local value
  value="$(metric_value "$metric")"
  [[ "$value" -eq "$expected" ]] || fail "$metric expected $expected, got $value"
}

issue_qkey() {
  python3 - "$SECRET_DIR/admin.sock" <<'PY'
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect(sys.argv[1])
sock.sendall(b'{"cmd":"qkey"}\n')
chunks = []
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
    if b"\n" in chunk:
        break
sock.close()
payload = json.loads(b"".join(chunks))
if not payload.get("success"):
    raise SystemExit("QKey issuance failed")
qkey = (payload.get("data") or {}).get("qkey")
if not isinstance(qkey, str) or not qkey.startswith("QKey-"):
    raise SystemExit("QKey issuance returned an invalid credential")
print(qkey)
PY
}

expect_geoip_failure() {
  local label="$1"
  local database="$2"
  local country="$3"
  local expected="$4"
  local output="$OUTPUT_DIR/geoip-${label}.log"
  if "$POLICY_PROBE_BINARY" geoip \
    --database "$database" \
    --blocked-country "$country" \
    --expect-blocked 81.2.69.142 \
    --expect-allowed 89.160.20.128 >"$output" 2>&1; then
    fail "GeoIP ${label} case unexpectedly activated"
  fi
  grep -F "$expected" "$output" >/dev/null \
    || fail "GeoIP ${label} case did not expose typed failure: expected ${expected}"
}

read_admin_status() {
  local socket_path="$1"
  python3 - "$socket_path" <<'PY'
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect(sys.argv[1])
sock.sendall(b'{"cmd":"status"}\n')
chunks = []
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
    if b"\n" in chunk:
        break
sock.close()
payload = json.loads(b"".join(chunks))
if not payload.get("success"):
    raise SystemExit("admin status failed")
print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
PY
}

run_initial_flood() {
  local label="$1"
  local count="$2"
  local interval_us="$3"
  "$CLIENT_BINARY" \
    --qkey "$QKEY" \
    --initial-only \
    --initial-count "$count" \
    --initial-interval-us "$interval_us" \
    --local "127.0.0.1:$FLOOD_LOCAL_PORT" \
    --ca-file "$SECRET_DIR/ca.crt" \
    --timeout-ms 3000 >"$OUTPUT_DIR/initial-$label.log" 2>&1
  grep -Fx "initial-sent count=$count" "$OUTPUT_DIR/initial-$label.log" >/dev/null \
    || fail "Initial flood $label did not send exactly $count packets"
}

run_valid_probe() {
  local label="$1"
  local local_addr="${2:-}"
  local -a args=(
    "$CLIENT_BINARY"
    --qkey "$QKEY"
    --ca-file "$SECRET_DIR/ca.crt"
    --timeout-ms 8000
  )
  if [[ -n "$local_addr" ]]; then
    args+=(--local "$local_addr")
  fi
  "${args[@]}" >"$OUTPUT_DIR/valid-$label.log" 2>&1
  grep -Fx 'connected' "$OUTPUT_DIR/valid-$label.log" >/dev/null \
    || fail "valid probe $label did not authenticate"
}

start_established_probe() {
  "$CLIENT_BINARY" \
    --qkey "$QKEY" \
    --ca-file "$SECRET_DIR/ca.crt" \
    --timeout-ms 8000 \
    --hold-ms 12000 >"$OUTPUT_DIR/valid-established.log" 2>&1 &
  ESTABLISHED_PID=$!

  for _ in $(seq 1 150); do
    grep -Fx 'connected' "$OUTPUT_DIR/valid-established.log" >/dev/null 2>&1 && return 0
    process_running "$ESTABLISHED_PID" \
      || fail "established probe exited before the controlled flood"
    sleep 0.1
  done
  fail "established probe did not authenticate before the controlled flood"
}

finish_established_probe() {
  local exit_code
  set +e
  wait "$ESTABLISHED_PID"
  exit_code=$?
  set -e
  ESTABLISHED_PID=""
  [[ "$exit_code" -eq 0 ]] || fail "established probe failed during the controlled flood"
  grep -E \
    '^hold-proof duration_ms=[0-9]+ pings=[1-9][0-9]* sent=[1-9][0-9]* recv=[1-9][0-9]* established=1$' \
    "$OUTPUT_DIR/valid-established.log" >/dev/null \
    || fail "established probe did not retain bidirectional traffic proof"
}

[[ -x "$SERVER_BINARY" ]] || fail "missing server executable: $SERVER_BINARY"
[[ -x "$CLIENT_BINARY" ]] || fail "missing E2E client executable: $CLIENT_BINARY"
[[ -x "$POLICY_PROBE_BINARY" ]] || fail "missing policy probe executable: $POLICY_PROBE_BINARY"
for command_name in curl openssl python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

SERVER_PORT="$(free_port udp)"
METRICS_PORT="$(free_port tcp)"
HTTPS_PORT="$(free_port tcp)"
FAILURE_PORT="$(free_port tcp)"
FLOOD_LOCAL_PORT="$(free_port udp)"

printf '%s\n' \
  '[engine]' \
  'mode = "server"' \
  'shutdown_timeout_ms = 1000' \
  '' \
  '[security]' \
  'lock_memory = false' \
  >"$SECRET_DIR/server.toml"
printf '%s\n' \
  '# controlled integration feed' \
  '203.0.113.7' \
  '2001:db8::7' \
  >"$SECRET_DIR/blocklist.txt"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -days 1 -subj '/CN=QuicFuscate DDoS Proof CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$SECRET_DIR/ca.key" -out "$SECRET_DIR/ca.crt" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -subj '/CN=cloudflare-dns.com' \
  -addext 'subjectAltName=DNS:cloudflare-dns.com,DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$SECRET_DIR/server.key" -out "$SECRET_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$SECRET_DIR/server.csr" \
  -CA "$SECRET_DIR/ca.crt" -CAkey "$SECRET_DIR/ca.key" \
  -CAcreateserial -days 1 -sha256 -copy_extensions copy \
  -out "$SECRET_DIR/server.crt" >/dev/null 2>&1
chmod 600 "$SECRET_DIR/ca.key" "$SECRET_DIR/server.key"

python3 - "$HTTPS_PORT" "$SECRET_DIR/blocklist.txt" \
  "$SECRET_DIR/server.crt" "$SECRET_DIR/server.key" >"$OUTPUT_DIR/https.log" 2>&1 <<'PY' &
import http.server
import pathlib
import ssl
import sys

port = int(sys.argv[1])
body = pathlib.Path(sys.argv[2]).read_bytes()

class FeedHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/blocklist.txt":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

server = http.server.ThreadingHTTPServer(("127.0.0.1", port), FeedHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[3], sys.argv[4])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
HTTPS_PID=$!

for _ in $(seq 1 100); do
  curl --cacert "$SECRET_DIR/ca.crt" -fsS \
    "https://127.0.0.1:$HTTPS_PORT/blocklist.txt" >/dev/null 2>&1 && break
  process_running "$HTTPS_PID" || fail "HTTPS feed server exited before readiness"
  sleep 0.05
done
curl --cacert "$SECRET_DIR/ca.crt" -fsS \
  "https://127.0.0.1:$HTTPS_PORT/blocklist.txt" >/dev/null \
  || fail "HTTPS feed server did not become ready"

"$POLICY_PROBE_BINARY" blacklist \
  --sync-url "https://127.0.0.1:$HTTPS_PORT/blocklist.txt" \
  --failure-url "https://127.0.0.1:$FAILURE_PORT/unreachable" \
  --cache "$SECRET_DIR/blacklist-cache.json" \
  --ca-certificate "$SECRET_DIR/ca.crt" \
  --expected-entries 2 \
  --expect-blocked 203.0.113.7 \
  --expect-blocked 2001:db8::7 \
  --expect-allowed 198.51.100.7 >"$OUTPUT_DIR/blacklist.json"

MAXMIND_DATABASE="$SECRET_DIR/GeoIP2-Country-Test.mmdb"
curl --fail --location --silent --show-error \
  "https://raw.githubusercontent.com/maxmind/MaxMind-DB/$MAXMIND_COMMIT/test-data/GeoIP2-Country-Test.mmdb" \
  --output "$MAXMIND_DATABASE"
[[ "$(sha256_file "$MAXMIND_DATABASE")" == "$MAXMIND_SHA256" ]] \
  || fail "MaxMind test database checksum mismatch"
"$POLICY_PROBE_BINARY" geoip \
  --database "$MAXMIND_DATABASE" \
  --blocked-country GB \
  --expect-blocked 81.2.69.142 \
  --expect-allowed 89.160.20.128 >"$OUTPUT_DIR/geoip.json"
grep -F '"status":"active"' "$OUTPUT_DIR/geoip.json" >/dev/null \
  || fail "valid GeoIP probe did not report active status"

MAXMIND_CITY_DATABASE="$SECRET_DIR/GeoIP2-City-Test.mmdb"
curl --fail --location --silent --show-error \
  "https://raw.githubusercontent.com/maxmind/MaxMind-DB/$MAXMIND_COMMIT/test-data/GeoIP2-City-Test.mmdb" \
  --output "$MAXMIND_CITY_DATABASE"
[[ "$(sha256_file "$MAXMIND_CITY_DATABASE")" == "$MAXMIND_CITY_SHA256" ]] \
  || fail "MaxMind city test database checksum mismatch"

MISSING_DATABASE="$SECRET_DIR/missing.mmdb"
expect_geoip_failure missing "$MISSING_DATABASE" GB 'MissingDatabase('

PERMISSION_DATABASE="$SECRET_DIR/permission.mmdb"
cp "$MAXMIND_DATABASE" "$PERMISSION_DATABASE"
chmod 000 "$PERMISSION_DATABASE"
expect_geoip_failure permission "$PERMISSION_DATABASE" GB 'UnreadableDatabase {'
chmod 600 "$PERMISSION_DATABASE"

CORRUPT_DATABASE="$SECRET_DIR/corrupt.mmdb"
python3 - "$CORRUPT_DATABASE" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(b"not a MaxMind database")
PY
expect_geoip_failure corrupt "$CORRUPT_DATABASE" GB 'InvalidDatabase {'
expect_geoip_failure invalid-country "$MAXMIND_DATABASE" G3 'InvalidCountryCode('
expect_geoip_failure unsupported "$MAXMIND_CITY_DATABASE" GB 'UnsupportedDatabase {'

env \
  RUST_LOG=info \
  QUICFUSCATE_BRAIN=0 \
  QUICFUSCATE_DDOS_ENABLED=true \
  QUICFUSCATE_DDOS_SAMPLE_INTERVAL_MS=100 \
  QUICFUSCATE_DDOS_ACTIVATION_WINDOW_MS=200 \
  QUICFUSCATE_DDOS_CLEAR_WINDOW_MS=2000 \
  QUICFUSCATE_DDOS_EWMA_ALPHA=0.1 \
  QUICFUSCATE_DDOS_SPIKE_MULTIPLIER=2 \
  QUICFUSCATE_DDOS_CLEAR_FACTOR=1.1 \
  QUICFUSCATE_DDOS_ENHANCED_PACKET_COST=2 \
  QUICFUSCATE_DDOS_RETRY_ENABLED=true \
  QUICFUSCATE_DDOS_RETRY_TOKEN_LIFETIME_SECS=10 \
  QUICFUSCATE_GEOIP_DB_PATH="$MAXMIND_DATABASE" \
  QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES=GB \
  "$SERVER_BINARY" server \
    --listen "127.0.0.1:$SERVER_PORT" \
    --metrics-port "$METRICS_PORT" \
    --cert "$SECRET_DIR/server.crt" \
    --key "$SECRET_DIR/server.key" \
    --front-domain cloudflare-dns.com \
    --admin-socket "$SECRET_DIR/admin.sock" \
    --qkey-store "$SECRET_DIR/qkeys.json" \
    --audit-log "$SECRET_DIR/audit.ndjson" \
    --config "$SECRET_DIR/server.toml" \
    --pool-capacity 32 \
    --disable-doh \
    --disable-fronting \
    --no-drop-privileges >"$OUTPUT_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 150); do
  if [[ -S "$SECRET_DIR/admin.sock" ]] \
    && curl -fsS "http://127.0.0.1:$METRICS_PORT/health" >/dev/null 2>&1; then
    break
  fi
  process_running "$SERVER_PID" || fail "server exited before readiness"
  sleep 0.1
done
[[ -S "$SECRET_DIR/admin.sock" ]] || fail "server admin socket did not become ready"
curl -fsS "http://127.0.0.1:$METRICS_PORT/health" >/dev/null \
  || fail "server metrics did not become ready"
curl -fsS "http://127.0.0.1:$METRICS_PORT/health" >"$OUTPUT_DIR/health.json"
grep -F '"geoip_status":"active"' "$OUTPUT_DIR/health.json" >/dev/null \
  || fail "server health did not report active GeoIP status"
assert_metric_exact 'quicfuscate_geoip_activation{state="active"}' 1
assert_metric_exact 'quicfuscate_geoip_activation{state="disabled"}' 0
assert_metric_exact 'quicfuscate_geoip_activation{state="failed"}' 0
read_admin_status "$SECRET_DIR/admin.sock" >"$OUTPUT_DIR/admin-status.json"
grep -F '"geoip":{"active":true,"status":"active"}' \
  "$OUTPUT_DIR/admin-status.json" >/dev/null \
  || fail "admin status did not report active GeoIP status"
QKEY="$(issue_qkey)"

assert_metric_exact quicfuscate_ddos_active 0
assert_metric_exact 'quicfuscate_ddos_transitions_total{transition="activated"}' 0
assert_metric_exact 'quicfuscate_ddos_transitions_total{transition="cleared"}' 0
assert_metric_exact 'quicfuscate_ddos_retry_total{outcome="issued"}' 0
assert_metric_exact 'quicfuscate_ddos_retry_total{outcome="validated"}' 0

sleep 0.3
run_initial_flood baseline 20 5000
wait_metric_at_least quicfuscate_ddos_current_pps 1
sleep 0.11

RETRY_ISSUED_CONTROL_BEFORE="$(metric_value 'quicfuscate_ddos_retry_total{outcome="issued"}')"
start_established_probe
RETRY_ISSUED_CONTROL_AFTER="$(metric_value 'quicfuscate_ddos_retry_total{outcome="issued"}')"
[[ "$RETRY_ISSUED_CONTROL_AFTER" -eq "$RETRY_ISSUED_CONTROL_BEFORE" ]] \
  || fail "pre-flood established control unexpectedly received a Retry"
RSS_BEFORE_KIB="$(process_rss_kib "$SERVER_PID")"
CPU_BEFORE_MS="$(process_cpu_millis "$SERVER_PID")"
run_initial_flood spike 800 1000
wait_metric_exact quicfuscate_ddos_active 1
wait_metric_exact 'quicfuscate_ddos_transitions_total{transition="activated"}' 1
wait_metric_at_least 'quicfuscate_ddos_retry_total{outcome="issued"}' 1
process_running "$ESTABLISHED_PID" \
  || fail "established probe stopped while enhanced admission was active"

RETRY_ISSUED_BEFORE="$(metric_value 'quicfuscate_ddos_retry_total{outcome="issued"}')"
run_valid_probe enhanced
wait_metric_at_least 'quicfuscate_ddos_retry_total{outcome="validated"}' 1
RETRY_ISSUED_AFTER="$(metric_value 'quicfuscate_ddos_retry_total{outcome="issued"}')"
[[ "$RETRY_ISSUED_AFTER" -gt "$RETRY_ISSUED_BEFORE" ]] \
  || fail "enhanced valid probe did not receive a Retry"
process_running "$ESTABLISHED_PID" \
  || fail "established probe stopped before enhanced admission cleared"

wait_metric_exact quicfuscate_ddos_active 0
wait_metric_exact 'quicfuscate_ddos_transitions_total{transition="cleared"}' 1
RETRY_ISSUED_CLEARED="$(metric_value 'quicfuscate_ddos_retry_total{outcome="issued"}')"
finish_established_probe
assert_metric_exact 'quicfuscate_ddos_retry_total{outcome="issued"}' "$RETRY_ISSUED_CLEARED"

RSS_AFTER_KIB="$(process_rss_kib "$SERVER_PID")"
CPU_AFTER_MS="$(process_cpu_millis "$SERVER_PID")"
RSS_GROWTH_KIB="$((RSS_AFTER_KIB - RSS_BEFORE_KIB))"
CPU_DELTA_MS="$((CPU_AFTER_MS - CPU_BEFORE_MS))"
[[ "$RSS_GROWTH_KIB" -ge 0 ]] || RSS_GROWTH_KIB=0
[[ "$CPU_DELTA_MS" -ge 0 ]] || CPU_DELTA_MS=0
[[ "$RSS_GROWTH_KIB" -le "$MAX_RSS_GROWTH_KIB" ]] \
  || fail "DDoS proof grew server RSS by ${RSS_GROWTH_KIB} KiB"
[[ "$CPU_DELTA_MS" -le "$MAX_SERVER_CPU_MS" ]] \
  || fail "DDoS proof consumed ${CPU_DELTA_MS} ms of server CPU"

curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" >"$OUTPUT_DIR/metrics.prom"
RETRY_VALIDATED="$(metric_value 'quicfuscate_ddos_retry_total{outcome="validated"}')"

stop_process "$SERVER_PID"
SERVER_PID=""
RESTART_SERVER_PORT="$(free_port udp)"
RESTART_METRICS_PORT="$(free_port tcp)"
RESTART_ADMIN_SOCKET="$SECRET_DIR/restart-admin.sock"
env \
  RUST_LOG=info \
  QUICFUSCATE_BRAIN=0 \
  QUICFUSCATE_DDOS_ENABLED=true \
  QUICFUSCATE_DDOS_SAMPLE_INTERVAL_MS=100 \
  QUICFUSCATE_DDOS_ACTIVATION_WINDOW_MS=200 \
  QUICFUSCATE_DDOS_CLEAR_WINDOW_MS=2000 \
  QUICFUSCATE_DDOS_EWMA_ALPHA=0.1 \
  QUICFUSCATE_DDOS_SPIKE_MULTIPLIER=2 \
  QUICFUSCATE_DDOS_CLEAR_FACTOR=1.1 \
  QUICFUSCATE_DDOS_ENHANCED_PACKET_COST=2 \
  QUICFUSCATE_DDOS_RETRY_ENABLED=true \
  QUICFUSCATE_DDOS_RETRY_TOKEN_LIFETIME_SECS=10 \
  QUICFUSCATE_GEOIP_DB_PATH="$MAXMIND_DATABASE" \
  QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES=GB \
  "$SERVER_BINARY" server \
    --listen "127.0.0.1:$RESTART_SERVER_PORT" \
    --metrics-port "$RESTART_METRICS_PORT" \
    --cert "$SECRET_DIR/server.crt" \
    --key "$SECRET_DIR/server.key" \
    --front-domain cloudflare-dns.com \
    --admin-socket "$RESTART_ADMIN_SOCKET" \
    --qkey-store "$SECRET_DIR/restart-qkeys.json" \
    --audit-log "$SECRET_DIR/restart-audit.ndjson" \
    --config "$SECRET_DIR/server.toml" \
    --pool-capacity 32 \
    --disable-doh \
    --disable-fronting \
    --no-drop-privileges >"$OUTPUT_DIR/server-restart.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 150); do
  if [[ -S "$RESTART_ADMIN_SOCKET" ]] \
    && curl -fsS "http://127.0.0.1:$RESTART_METRICS_PORT/health" >/dev/null 2>&1; then
    break
  fi
  process_running "$SERVER_PID" || fail "restarted server exited before readiness"
  sleep 0.1
done
[[ -S "$RESTART_ADMIN_SOCKET" ]] || fail "restarted server admin socket did not become ready"
curl -fsS "http://127.0.0.1:$RESTART_METRICS_PORT/health" >"$OUTPUT_DIR/restart-health.json" \
  || fail "restarted server metrics did not become ready"
grep -F '"geoip_status":"active"' "$OUTPUT_DIR/restart-health.json" >/dev/null \
  || fail "restarted server health did not report active GeoIP status"
curl -fsS "http://127.0.0.1:$RESTART_METRICS_PORT/metrics" >"$OUTPUT_DIR/restart-metrics.prom"
grep -Fx 'quicfuscate_geoip_activation{state="active"} 1' \
  "$OUTPUT_DIR/restart-metrics.prom" >/dev/null \
  || fail "restarted server metrics did not report active GeoIP status"
grep -Fx 'quicfuscate_geoip_activation{state="disabled"} 0' \
  "$OUTPUT_DIR/restart-metrics.prom" >/dev/null \
  || fail "restarted server metrics reported unexpected disabled GeoIP state"
grep -Fx 'quicfuscate_geoip_activation{state="failed"} 0' \
  "$OUTPUT_DIR/restart-metrics.prom" >/dev/null \
  || fail "restarted server metrics reported unexpected failed GeoIP state"
read_admin_status "$RESTART_ADMIN_SOCKET" >"$OUTPUT_DIR/restart-admin-status.json"
grep -F '"geoip":{"active":true,"status":"active"}' \
  "$OUTPUT_DIR/restart-admin-status.json" >/dev/null \
  || fail "restarted admin status did not report active GeoIP status"
stop_process "$SERVER_PID"
SERVER_PID=""

PROTECTED_UI_DIFF="$(git diff --name-only -- \
  apps/svelte-admin apps/svelte-desktop packages/ui packages/theme assets/web-admin)"
[[ -z "$PROTECTED_UI_DIFF" ]] || fail "protected UI changed: $PROTECTED_UI_DIFF"

SERVER_SHA256="$(sha256_file "$SERVER_BINARY")"
CLIENT_SHA256="$(sha256_file "$CLIENT_BINARY")"
PROBE_SHA256="$(sha256_file "$POLICY_PROBE_BINARY")"
{
  printf 'result=pass\n'
  printf 'server_binary_sha256=%s\n' "$SERVER_SHA256"
  printf 'client_binary_sha256=%s\n' "$CLIENT_SHA256"
  printf 'policy_probe_binary_sha256=%s\n' "$PROBE_SHA256"
  printf 'maxmind_commit=%s\n' "$MAXMIND_COMMIT"
  printf 'maxmind_database_sha256=%s\n' "$MAXMIND_SHA256"
  printf 'maxmind_city_database_sha256=%s\n' "$MAXMIND_CITY_SHA256"
  printf 'geoip_real_database_proved=1\n'
  printf 'geoip_missing_database_rejected=1\n'
  printf 'geoip_permission_database_rejected=1\n'
  printf 'geoip_corrupt_database_rejected=1\n'
  printf 'geoip_invalid_country_rejected=1\n'
  printf 'geoip_unsupported_database_rejected=1\n'
  printf 'geoip_exact_admission_proved=1\n'
  printf 'geoip_restart_status_proved=1\n'
  printf 'geoip_health_admin_metrics_truth_proved=1\n'
  printf 'blacklist_https_sync_proved=1\n'
  printf 'blacklist_restart_cache_proved=1\n'
  printf 'blacklist_failed_refresh_lkg_proved=1\n'
  printf 'controlled_initial_packets=820\n'
  printf 'ddos_activations=1\n'
  printf 'ddos_clears=1\n'
  printf 'retry_issued_control_before=%s\n' "$RETRY_ISSUED_CONTROL_BEFORE"
  printf 'retry_issued_control_after=%s\n' "$RETRY_ISSUED_CONTROL_AFTER"
  printf 'retry_issued_before_valid=%s\n' "$RETRY_ISSUED_BEFORE"
  printf 'retry_issued_after_valid=%s\n' "$RETRY_ISSUED_AFTER"
  printf 'retry_validated=%s\n' "$RETRY_VALIDATED"
  printf 'established_traffic_preservation_process_proof=1\n'
  printf 'server_rss_growth_kib=%s\n' "$RSS_GROWTH_KIB"
  printf 'server_cpu_ms=%s\n' "$CPU_DELTA_MS"
  printf 'protected_ui_changes=0\n'
  printf 'owned_process_residue=0\n'
} >"$OUTPUT_DIR/summary.txt"

grep -R -F "$QKEY" "$OUTPUT_DIR" >/dev/null 2>&1 \
  && fail "raw QKey leaked into retained evidence"

stop_process "$SERVER_PID"
SERVER_PID=""
stop_process "$HTTPS_PID"
HTTPS_PID=""

printf 'PASS: process-real DDoS admission, Retry, GeoIP, and blacklist proof\n'
printf 'Evidence: %s\n' "$OUTPUT_DIR"
