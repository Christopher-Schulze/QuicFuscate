#!/usr/bin/env bash
# Description: Process-real QKey auth backoff, block, isolation, prune, and flood proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

SERVER_BINARY="${QUICFUSCATE_TEST_BINARY:-$PROJECT_ROOT/target/debug/quicfuscate}"
PROBE_BINARY="${QUICFUSCATE_AUTH_PROBE_BINARY:-$PROJECT_ROOT/target/debug/qf-e2e-client}"
OUTPUT_DIR=""
SECONDARY_LOCAL="${QUICFUSCATE_AUTH_SECONDARY_LOCAL:-127.0.0.2:0}"
REQUIRE_SECONDARY_IP=1
MAX_RSS_GROWTH_KIB="${QUICFUSCATE_AUTH_MAX_RSS_GROWTH_KIB:-32768}"
MAX_SERVER_CPU_MS="${QUICFUSCATE_AUTH_MAX_SERVER_CPU_MS:-10000}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-binary)
      SERVER_BINARY="$2"
      shift 2
      ;;
    --probe-binary)
      PROBE_BINARY="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --secondary-local)
      SECONDARY_LOCAL="$2"
      shift 2
      ;;
    --skip-secondary-ip)
      REQUIRE_SECONDARY_IP=0
      shift
      ;;
    --help|-h)
      echo "Usage: $(basename "$0") [--server-binary PATH] [--probe-binary PATH] [--output-dir DIR] [--secondary-local ADDR] [--skip-secondary-ip]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$PROJECT_ROOT/scripts/out/tests/qkey-auth-policy-$(date +%Y%m%d_%H%M%S)"
fi
if [[ -e "$OUTPUT_DIR" ]]; then
  echo "error: refusing existing output path: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUTPUT_DIR")"
mkdir "$OUTPUT_DIR"

TEMP_ROOT="${TMPDIR:-/tmp}"
TEMP_ROOT="${TEMP_ROOT%/}"
SECRET_DIR="$(mktemp -d "$TEMP_ROOT/quicfuscate-auth-policy.XXXXXX")"
SERVER_PID=""
SERVER_PORT=""
METRICS_PORT=""
ACTIVE_PHASE=""
QKEY=""
INVALID_INITIAL_TOKEN=""

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

stop_server() {
  local status=0
  [[ -n "$SERVER_PID" ]] || return 0
  if process_running "$SERVER_PID"; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 100); do
      process_running "$SERVER_PID" || break
      sleep 0.1
    done
  fi
  if process_running "$SERVER_PID"; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    fail "server did not stop within 10 seconds"
  fi
  wait "$SERVER_PID" || status=$?
  SERVER_PID=""
  [[ "$status" -eq 0 ]] || fail "server exited with status $status"
}

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
  case "$SECRET_DIR" in
    "$TEMP_ROOT"/quicfuscate-auth-policy.*)
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
  if [[ -n "$ACTIVE_PHASE" && -f "$OUTPUT_DIR/server-$ACTIVE_PHASE.log" ]]; then
    tail -n 100 "$OUTPUT_DIR/server-$ACTIVE_PHASE.log" >&2 || true
  fi
  printf 'FAIL: QKey auth-policy harness stopped at line %s with exit %s\n' \
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
  local raw
  raw="$(ps -p "$1" -o cputime= | tr -d ' ')"
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

wait_ready() {
  for _ in $(seq 1 150); do
    if [[ -S "$SECRET_DIR/admin.sock" ]] \
      && curl -fsS "http://127.0.0.1:$METRICS_PORT/health" >/dev/null 2>&1; then
      return 0
    fi
    process_running "$SERVER_PID" || return 1
    sleep 0.1
  done
  return 1
}

fetch_metrics() {
  local destination="$1"
  curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" >"$destination"
}

metric_value() {
  local metric="$1"
  local line
  line="$(curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" | awk -v metric="$metric" '$1 == metric {print $2}')"
  [[ "$line" =~ ^[0-9]+$ ]] || fail "metric $metric is missing or non-integral: $line"
  printf '%s\n' "$line"
}

wait_metric_exact() {
  local metric="$1"
  local expected="$2"
  local value=""
  for _ in $(seq 1 200); do
    value="$(metric_value "$metric")"
    [[ "$value" -eq "$expected" ]] && return 0
    [[ "$value" -lt "$expected" ]] || fail "$metric exceeded $expected with $value"
    sleep 0.02
  done
  fail "$metric did not reach $expected, last value $value"
}

wait_metric_value() {
  local metric="$1"
  local expected="$2"
  local value=""
  for _ in $(seq 1 200); do
    value="$(metric_value "$metric")"
    [[ "$value" -eq "$expected" ]] && return 0
    sleep 0.02
  done
  fail "$metric did not become $expected, last value $value"
}

assert_metric_exact() {
  local metric="$1"
  local expected="$2"
  local value
  value="$(metric_value "$metric")"
  [[ "$value" -eq "$expected" ]] || fail "$metric expected $expected, got $value"
}

assert_metric_at_least() {
  local metric="$1"
  local minimum="$2"
  local value
  value="$(metric_value "$metric")"
  [[ "$value" -ge "$minimum" ]] || fail "$metric expected at least $minimum, got $value"
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

derive_invalid_initial_token() {
  python3 -c '
import hashlib
import sys
qkey = sys.stdin.read().strip()
canonical = "QKey-" + qkey[5:] if qkey[:5].lower() == "qkey-" else qkey
issued = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
print("ffffffffffff" if issued == "000000000000" else "000000000000")
'
}

run_initial_probe() {
  local attempt="$1"
  local local_addr="${2:-}"
  local -a args=(
    "$PROBE_BINARY"
    --qkey "$QKEY"
    --initial-token "$INVALID_INITIAL_TOKEN"
    --initial-only
    --ca-file "$SECRET_DIR/ca.crt"
    --timeout-ms 2000
  )
  if [[ -n "$local_addr" ]]; then
    args+=(--local "$local_addr")
  fi
  printf 'attempt=%s ' "$attempt" >>"$OUTPUT_DIR/probes-$ACTIVE_PHASE.log"
  "${args[@]}" >>"$OUTPUT_DIR/probes-$ACTIVE_PHASE.log" 2>&1
}

run_valid_probe() {
  local label="$1"
  local local_addr="${2:-}"
  local -a args=(
    "$PROBE_BINARY"
    --qkey "$QKEY"
    --ca-file "$SECRET_DIR/ca.crt"
    --timeout-ms 5000
  )
  if [[ -n "$local_addr" ]]; then
    args+=(--local "$local_addr")
  fi
  "${args[@]}" >"$OUTPUT_DIR/valid-$label.log" 2>&1
  grep -Fx 'connected' "$OUTPUT_DIR/valid-$label.log" >/dev/null \
    || fail "valid probe $label did not authenticate"
}

start_server() {
  local phase="$1"
  local block_duration_secs="$2"
  ACTIVE_PHASE="$phase"
  rm -f "$SECRET_DIR/admin.sock"
  env \
    RUST_LOG=info \
    QUICFUSCATE_BRAIN=0 \
    QUICFUSCATE_AUTH_POLICY_ENABLED=true \
    QUICFUSCATE_AUTH_BACKOFF_AFTER_FAILURES=2 \
    QUICFUSCATE_AUTH_BACKOFF_BASE_MS=500 \
    QUICFUSCATE_AUTH_BACKOFF_MAX_MS=1000 \
    QUICFUSCATE_AUTH_BLOCK_AFTER_FAILURES=4 \
    "QUICFUSCATE_AUTH_BLOCK_DURATION_SECS=$block_duration_secs" \
    QUICFUSCATE_AUTH_IDLE_TIMEOUT_SECS=3 \
    QUICFUSCATE_AUTH_PRUNE_INTERVAL_SECS=1 \
    QUICFUSCATE_AUTH_MAX_TRACKED_IPS=16 \
    QUICFUSCATE_AUTH_MAX_PENDING_PER_IP=4 \
    "$SERVER_BINARY" server \
      --listen "127.0.0.1:$SERVER_PORT" \
      --metrics-port "$METRICS_PORT" \
      --cert "$SECRET_DIR/server.crt" \
      --key "$SECRET_DIR/server.key" \
      --front-domain cloudflare-dns.com \
      --admin-socket "$SECRET_DIR/admin.sock" \
      --qkey-store "$SECRET_DIR/qkeys.json" \
      --audit-log "$SECRET_DIR/audit-$phase.ndjson" \
      --config "$SECRET_DIR/server.toml" \
      --pool-capacity 16 \
      --disable-doh \
      --disable-fronting \
      --no-drop-privileges >"$OUTPUT_DIR/server-$phase.log" 2>&1 &
  SERVER_PID=$!
  wait_ready || {
    tail -n 100 "$OUTPUT_DIR/server-$phase.log" >&2
    fail "server did not become ready for phase $phase"
  }
  QKEY="$(issue_qkey)"
  INVALID_INITIAL_TOKEN="$(printf '%s' "$QKEY" | derive_invalid_initial_token)"
}

preserve_audit() {
  local phase="$1"
  cp "$SECRET_DIR/audit-$phase.ndjson" "$OUTPUT_DIR/audit-$phase.ndjson"
}

verify_audit_counts() {
  local phase="$1"
  local initial_denials="$2"
  local backoff_denials="$3"
  local blocked_denials="$4"
  local successes="$5"
  python3 - "$OUTPUT_DIR/audit-$phase.ndjson" \
    "$initial_denials" "$backoff_denials" "$blocked_denials" "$successes" <<'PY'
import json
import sys

path = sys.argv[1]
expected = {
    "qkey_initial_auth_denied": int(sys.argv[2]),
    "qkey_auth_backoff": int(sys.argv[3]),
    "qkey_auth_blocked": int(sys.argv[4]),
}
events = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
for reason, count in expected.items():
    actual = sum(event.get("reason") == reason for event in events)
    if actual != count:
        raise SystemExit(f"{reason}: expected {count}, got {actual}")
successes = sum(event.get("event") == "client_authenticated" for event in events)
if successes != int(sys.argv[5]):
    raise SystemExit(f"client_authenticated: expected {sys.argv[5]}, got {successes}")
for index, event in enumerate(events):
    if event.get("seq") != index:
        raise SystemExit(f"audit sequence mismatch at row {index}")
    if event.get("version") != 2:
        raise SystemExit(f"audit version mismatch at row {index}")
PY
}

run_invalid_config_probe() {
  local invalid_socket="$SECRET_DIR/invalid-admin.sock"
  local invalid_store="$SECRET_DIR/invalid-qkeys.json"
  local invalid_audit="$SECRET_DIR/invalid-audit.ndjson"
  local invalid_log="$OUTPUT_DIR/invalid-config.log"
  local invalid_pid
  local status=0

  env \
    QUICFUSCATE_BRAIN=0 \
    QUICFUSCATE_AUTH_BACKOFF_AFTER_FAILURES=0 \
    "$SERVER_BINARY" server \
      --listen "127.0.0.1:$SERVER_PORT" \
      --cert "$SECRET_DIR/server.crt" \
      --key "$SECRET_DIR/server.key" \
      --admin-socket "$invalid_socket" \
      --qkey-store "$invalid_store" \
      --audit-log "$invalid_audit" \
      --config "$SECRET_DIR/server.toml" \
      --no-drop-privileges >"$invalid_log" 2>&1 &
  invalid_pid=$!
  for _ in $(seq 1 50); do
    process_running "$invalid_pid" || break
    sleep 0.05
  done
  if process_running "$invalid_pid"; then
    kill -KILL "$invalid_pid" 2>/dev/null || true
    wait "$invalid_pid" 2>/dev/null || true
    fail "invalid auth policy did not fail closed before startup"
  fi
  wait "$invalid_pid" || status=$?
  [[ "$status" -ne 0 ]] || fail "invalid auth policy returned success"
  grep -F 'auth backoff threshold must be at least 1' "$invalid_log" >/dev/null \
    || fail "invalid auth policy did not report its exact validation error"
  [[ ! -e "$invalid_socket" ]] || fail "invalid config created an admin socket"
  [[ ! -e "$invalid_store" ]] || fail "invalid config created QKey state"
  [[ ! -e "$invalid_audit" ]] || fail "invalid config created audit state"
}

[[ -x "$SERVER_BINARY" ]] || fail "missing server executable: $SERVER_BINARY"
[[ -x "$PROBE_BINARY" ]] || fail "missing auth probe executable: $PROBE_BINARY"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

SERVER_PORT="$(free_port udp)"
METRICS_PORT="$(free_port tcp)"

printf '%s\n' \
  '[engine]' \
  'mode = "server"' \
  'shutdown_timeout_ms = 1000' \
  '' \
  '[security]' \
  'lock_memory = false' \
  >"$SECRET_DIR/server.toml"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -days 1 -subj '/CN=QuicFuscate Auth Policy Proof CA' \
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

run_invalid_config_probe

start_server lifecycle 2
for metric in \
  quicfuscate_auth_attempts_total \
  quicfuscate_auth_succeeded_total \
  quicfuscate_auth_failed_total \
  quicfuscate_auth_backoff_rejected_total \
  quicfuscate_auth_blocked_rejected_total \
  quicfuscate_auth_capacity_rejected_total \
  quicfuscate_auth_abandoned_total \
  quicfuscate_auth_state_tracked_ips \
  quicfuscate_auth_state_pruned_total; do
  assert_metric_exact "$metric" 0
done

run_initial_probe 1
wait_metric_exact quicfuscate_auth_failed_total 1
run_initial_probe 2
wait_metric_exact quicfuscate_auth_failed_total 2
run_initial_probe 3
wait_metric_exact quicfuscate_auth_backoff_rejected_total 1
sleep 0.6
run_initial_probe 4
wait_metric_exact quicfuscate_auth_failed_total 3
run_initial_probe 5
wait_metric_exact quicfuscate_auth_backoff_rejected_total 2
sleep 1.1
run_initial_probe 6
wait_metric_exact quicfuscate_auth_failed_total 4
run_initial_probe 7
wait_metric_exact quicfuscate_auth_blocked_rejected_total 1

LIFECYCLE_SUCCESSES=1
LIFECYCLE_ATTEMPTS=9
if [[ "$REQUIRE_SECONDARY_IP" -eq 1 ]]; then
  run_valid_probe secondary "$SECONDARY_LOCAL"
  wait_metric_exact quicfuscate_auth_succeeded_total 1
  LIFECYCLE_SUCCESSES=2
  LIFECYCLE_ATTEMPTS=10
fi

sleep 2.2
run_valid_probe primary
wait_metric_exact quicfuscate_auth_succeeded_total "$LIFECYCLE_SUCCESSES"
run_initial_probe "$((LIFECYCLE_ATTEMPTS - 1))"
wait_metric_exact quicfuscate_auth_failed_total 5
wait_metric_exact quicfuscate_auth_attempts_total "$LIFECYCLE_ATTEMPTS"
assert_metric_exact quicfuscate_auth_backoff_rejected_total 2
assert_metric_exact quicfuscate_auth_blocked_rejected_total 1
assert_metric_exact quicfuscate_auth_capacity_rejected_total 0
assert_metric_exact quicfuscate_auth_abandoned_total 0
sleep 3.2
wait_metric_value quicfuscate_auth_state_tracked_ips 0
assert_metric_at_least quicfuscate_auth_state_pruned_total 1
fetch_metrics "$OUTPUT_DIR/metrics-lifecycle.prom"
stop_server
preserve_audit lifecycle
verify_audit_counts lifecycle 5 2 1 "$LIFECYCLE_SUCCESSES"

start_server flood 300
RSS_BEFORE_KIB="$(process_rss_kib "$SERVER_PID")"
CPU_BEFORE_MS="$(process_cpu_millis "$SERVER_PID")"
run_initial_probe 1
wait_metric_exact quicfuscate_auth_failed_total 1
run_initial_probe 2
wait_metric_exact quicfuscate_auth_failed_total 2
run_initial_probe 3
wait_metric_exact quicfuscate_auth_backoff_rejected_total 1
sleep 0.6
run_initial_probe 4
wait_metric_exact quicfuscate_auth_failed_total 3
run_initial_probe 5
wait_metric_exact quicfuscate_auth_backoff_rejected_total 2
sleep 1.1
run_initial_probe 6
wait_metric_exact quicfuscate_auth_failed_total 4
for attempt in $(seq 7 100); do
  run_initial_probe "$attempt"
  wait_metric_exact quicfuscate_auth_attempts_total "$attempt"
done

RSS_AFTER_KIB="$(process_rss_kib "$SERVER_PID")"
CPU_AFTER_MS="$(process_cpu_millis "$SERVER_PID")"
RSS_GROWTH_KIB="$((RSS_AFTER_KIB - RSS_BEFORE_KIB))"
CPU_DELTA_MS="$((CPU_AFTER_MS - CPU_BEFORE_MS))"
[[ "$RSS_GROWTH_KIB" -ge 0 ]] || RSS_GROWTH_KIB=0
[[ "$CPU_DELTA_MS" -ge 0 ]] || CPU_DELTA_MS=0
[[ "$RSS_GROWTH_KIB" -le "$MAX_RSS_GROWTH_KIB" ]] \
  || fail "100-attempt flood grew server RSS by ${RSS_GROWTH_KIB} KiB"
[[ "$CPU_DELTA_MS" -le "$MAX_SERVER_CPU_MS" ]] \
  || fail "100-attempt flood consumed ${CPU_DELTA_MS} ms of server CPU"

assert_metric_exact quicfuscate_auth_attempts_total 100
assert_metric_exact quicfuscate_auth_succeeded_total 0
assert_metric_exact quicfuscate_auth_failed_total 4
assert_metric_exact quicfuscate_auth_backoff_rejected_total 2
assert_metric_exact quicfuscate_auth_blocked_rejected_total 94
assert_metric_exact quicfuscate_auth_capacity_rejected_total 0
assert_metric_exact quicfuscate_auth_abandoned_total 0
assert_metric_exact quicfuscate_auth_state_tracked_ips 1
assert_metric_exact quicfuscate_rate_limited_total 96
fetch_metrics "$OUTPUT_DIR/metrics-flood.prom"
stop_server
preserve_audit flood
verify_audit_counts flood 4 2 94 0

PROTECTED_UI_DIFF="$(git diff --name-only -- \
  apps/svelte-admin apps/svelte-desktop packages/ui packages/theme assets/web-admin)"
[[ -z "$PROTECTED_UI_DIFF" ]] || fail "protected UI changed: $PROTECTED_UI_DIFF"

SERVER_SHA256="$(sha256_file "$SERVER_BINARY")"
PROBE_SHA256="$(sha256_file "$PROBE_BINARY")"
{
  printf 'result=pass\n'
  printf 'server_binary_sha256=%s\n' "$SERVER_SHA256"
  printf 'probe_binary_sha256=%s\n' "$PROBE_SHA256"
  printf 'invalid_config_rejections=1\n'
  printf 'lifecycle_attempts=%s\n' "$LIFECYCLE_ATTEMPTS"
  printf 'lifecycle_successes=%s\n' "$LIFECYCLE_SUCCESSES"
  printf 'second_ip_proved=%s\n' "$REQUIRE_SECONDARY_IP"
  printf 'flood_attempts=100\n'
  printf 'flood_failed=4\n'
  printf 'flood_backoff_rejected=2\n'
  printf 'flood_blocked_rejected=94\n'
  printf 'flood_state_tracked_ips=1\n'
  printf 'flood_server_rss_before_kib=%s\n' "$RSS_BEFORE_KIB"
  printf 'flood_server_rss_after_kib=%s\n' "$RSS_AFTER_KIB"
  printf 'flood_server_rss_growth_kib=%s\n' "$RSS_GROWTH_KIB"
  printf 'flood_server_cpu_ms=%s\n' "$CPU_DELTA_MS"
  printf 'protected_ui_changes=0\n'
  printf 'owned_process_residue=0\n'
} >"$OUTPUT_DIR/summary.txt"

grep -R -F "$QKEY" "$OUTPUT_DIR" >/dev/null 2>&1 \
  && fail "raw QKey leaked into retained evidence"
if process_running "$SERVER_PID"; then
  fail "owned server process remains"
fi

printf 'PASS: QKey auth-policy lifecycle and 100-attempt flood proof\n'
printf 'Evidence: %s\n' "$OUTPUT_DIR"
