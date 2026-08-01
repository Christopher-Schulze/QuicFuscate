#!/usr/bin/env bash
# Description: Process-real QKey registry encryption, restart, rejection, and rotation proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

BINARY="${QUICFUSCATE_TEST_BINARY:-$PROJECT_ROOT/target/debug/quicfuscate}"
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $(basename "$0") [--binary PATH] [--output-dir DIR]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$PROJECT_ROOT/scripts/out/tests/qkey-registry-encryption-$(date +%Y%m%d_%H%M%S)"
fi
if [[ -e "$OUTPUT_DIR" ]]; then
  echo "error: refusing existing output path: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUTPUT_DIR")"
mkdir "$OUTPUT_DIR"

SERVER_PID=""
OLD_KEY="$OUTPUT_DIR/current-old.key"
NEW_KEY="$OUTPUT_DIR/current-new.key"
WRONG_KEY="$OUTPUT_DIR/wrong.key"
SERVER_KEY="$OUTPUT_DIR/server.key"
CA_KEY="$OUTPUT_DIR/ca.key"

process_running() {
  local pid="$1"
  local state
  state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ' || true)"
  [[ -n "$state" && "$state" != Z* ]]
}

stop_server() {
  [[ -n "$SERVER_PID" ]] || return 0
  if process_running "$SERVER_PID"; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      process_running "$SERVER_PID" || break
      sleep 0.1
    done
  fi
  if process_running "$SERVER_PID"; then
    kill -KILL "$SERVER_PID" 2>/dev/null || true
  fi
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

cleanup() {
  stop_server
  rm -f \
    "$OLD_KEY" \
    "$NEW_KEY" \
    "$WRONG_KEY" \
    "$SERVER_KEY" \
    "$CA_KEY" \
    "$OUTPUT_DIR/server.csr" \
    "$OUTPUT_DIR/ca.srl"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

free_udp_port() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

wait_ready() {
  local log_file="$1"
  for _ in $(seq 1 150); do
    grep -F 'Server listening on ' "$log_file" >/dev/null 2>&1 && return 0
    process_running "$SERVER_PID" || return 1
    sleep 0.1
  done
  return 1
}

wait_failed() {
  local log_file="$1"
  local pattern="$2"
  local status
  for _ in $(seq 1 100); do
    if ! process_running "$SERVER_PID"; then
      grep -F "$pattern" "$log_file" >/dev/null 2>&1 || {
        tail -n 80 "$log_file" >&2
        fail "failed startup did not report: $pattern"
      }
      status=0
      wait "$SERVER_PID" 2>/dev/null || status=$?
      [[ "$status" -ne 0 ]] || fail "rejected startup returned success"
      SERVER_PID=""
      return 0
    fi
    sleep 0.1
  done
  fail "rejected startup remained alive"
}

start_server() {
  local log_file="$1"
  local current_key="$2"
  local previous_key="${3:-}"
  local env_args=(
    env
    RUST_LOG=info
    QUICFUSCATE_BRAIN=0
    "QUICFUSCATE_QKEY_ENC_KEY_FILE=$current_key"
  )
  if [[ -n "$previous_key" ]]; then
    env_args+=("QUICFUSCATE_QKEY_ENC_PREVIOUS_KEY_FILE=$previous_key")
  fi
  "${env_args[@]}" "$BINARY" server \
    --listen "127.0.0.1:$SERVER_PORT" \
    --cert "$SERVER_CERT" \
    --key "$SERVER_KEY" \
    --config "$CONFIG" \
    --qkey-store "$REGISTRY" \
    --pool-capacity 16 \
    --disable-doh \
    --disable-fronting \
    --no-drop-privileges >"$log_file" 2>&1 &
  SERVER_PID=$!
}

capture_command_line() {
  local destination="$1"
  if [[ -r "/proc/$SERVER_PID/cmdline" ]]; then
    tr '\0' '\n' <"/proc/$SERVER_PID/cmdline" >"$destination"
  else
    ps -p "$SERVER_PID" -o command= >"$destination"
  fi
}

[[ -x "$BINARY" ]] || fail "missing executable: $BINARY"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v od >/dev/null 2>&1 || fail "od is required"

SERVER_PORT="$(free_udp_port)"
REGISTRY="$OUTPUT_DIR/qkeys.json"
BACKUP="$OUTPUT_DIR/qkeys.json.backup"
CONFIG="$OUTPUT_DIR/server.toml"
CA_CERT="$OUTPUT_DIR/ca.crt"
SERVER_CERT="$OUTPUT_DIR/server.crt"
TOKEN_HASH="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

printf '%s\n' \
  '[engine]' \
  'mode = "server"' \
  'shutdown_timeout_ms = 1000' \
  '' \
  '[security]' \
  'lock_memory = false' \
  >"$CONFIG"
printf '%s\n' \
  '[{"id":"a1b2c3d4e5f6","token_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":1}]' \
  >"$REGISTRY"
chmod 600 "$REGISTRY"

openssl rand 32 >"$OLD_KEY"
openssl rand 32 >"$NEW_KEY"
openssl rand 32 >"$WRONG_KEY"
chmod 600 "$OLD_KEY" "$NEW_KEY" "$WRONG_KEY"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -days 1 -subj '/CN=QuicFuscate QKey Registry Proof CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$CA_KEY" -out "$CA_CERT" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$SERVER_KEY" -out "$OUTPUT_DIR/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$OUTPUT_DIR/server.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$SERVER_CERT" >/dev/null 2>&1
chmod 600 "$CA_KEY" "$SERVER_KEY"

start_server "$OUTPUT_DIR/migration.log" "$OLD_KEY"
wait_ready "$OUTPUT_DIR/migration.log" || {
  tail -n 100 "$OUTPUT_DIR/migration.log" >&2
  fail "plaintext migration startup failed"
}
capture_command_line "$OUTPUT_DIR/migration.cmdline"
OLD_KEY_HEX="$(od -An -v -tx1 "$OLD_KEY" | tr -d ' \n')"
grep -F "$OLD_KEY_HEX" "$OUTPUT_DIR/migration.cmdline" >/dev/null 2>&1 \
  && fail "master key leaked into process arguments"
grep -F "$TOKEN_HASH" "$OUTPUT_DIR/migration.log" "$OUTPUT_DIR/migration.cmdline" \
  >/dev/null 2>&1 && fail "token hash leaked into logs or process arguments"
[[ "$(head -c 6 "$REGISTRY")" == "QFQREG" ]] || fail "primary was not migrated"
[[ "$(head -c 6 "$BACKUP")" == "QFQREG" ]] || fail "backup was not encrypted"
[[ "$(file_mode "$REGISTRY")" == "640" ]] || fail "primary mode is not 640"
[[ "$(file_mode "$BACKUP")" == "640" ]] || fail "backup mode is not 640"
grep -aF "$TOKEN_HASH" "$REGISTRY" "$BACKUP" >/dev/null 2>&1 \
  && fail "token hash is visible in encrypted storage"
OLD_PRIMARY_SHA256="$(sha256_file "$REGISTRY")"
OLD_BACKUP_SHA256="$(sha256_file "$BACKUP")"
BINARY_SHA256="$(sha256_file "$BINARY")"
stop_server

start_server "$OUTPUT_DIR/restart-old.log" "$OLD_KEY"
wait_ready "$OUTPUT_DIR/restart-old.log" || {
  tail -n 100 "$OUTPUT_DIR/restart-old.log" >&2
  fail "same-key restart failed"
}
[[ "$(sha256_file "$REGISTRY")" == "$OLD_PRIMARY_SHA256" ]] \
  || fail "same-key restart rewrote durable state"
stop_server

cp "$REGISTRY" "$OUTPUT_DIR/qkeys.good"
python3 - "$REGISTRY" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(
    '[{"id":"ffffffffffff","token_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","created_at":2}]\n',
    encoding="utf-8",
)
PY
chmod 600 "$REGISTRY"
start_server "$OUTPUT_DIR/plaintext-downgrade.log" "$OLD_KEY"
wait_failed \
  "$OUTPUT_DIR/plaintext-downgrade.log" \
  'plaintext primary does not match the encrypted recovery backup'
[[ "$(sha256_file "$BACKUP")" == "$OLD_BACKUP_SHA256" ]] \
  || fail "plaintext downgrade startup mutated recovery backup"
mv "$REGISTRY" "$OUTPUT_DIR/qkeys.downgraded"
cp "$OUTPUT_DIR/qkeys.good" "$REGISTRY"
chmod 600 "$REGISTRY"

start_server "$OUTPUT_DIR/wrong-key.log" "$WRONG_KEY"
wait_failed "$OUTPUT_DIR/wrong-key.log" 'WrongKey'
[[ "$(sha256_file "$REGISTRY")" == "$OLD_PRIMARY_SHA256" ]] \
  || fail "wrong-key startup mutated durable state"

python3 - "$REGISTRY" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 0x80
path.write_bytes(data)
PY
start_server "$OUTPUT_DIR/tamper.log" "$OLD_KEY"
wait_failed "$OUTPUT_DIR/tamper.log" 'Corrupt("authentication failed")'
mv "$REGISTRY" "$OUTPUT_DIR/qkeys.tampered"
cp "$OUTPUT_DIR/qkeys.good" "$REGISTRY"
chmod 600 "$REGISTRY"

start_server "$OUTPUT_DIR/rotation.log" "$NEW_KEY" "$OLD_KEY"
wait_ready "$OUTPUT_DIR/rotation.log" || {
  tail -n 100 "$OUTPUT_DIR/rotation.log" >&2
  fail "current/previous-key rotation failed"
}
NEW_PRIMARY_SHA256="$(sha256_file "$REGISTRY")"
[[ "$NEW_PRIMARY_SHA256" != "$OLD_PRIMARY_SHA256" ]] || fail "rotation did not rewrite primary"
[[ "$(sha256_file "$BACKUP")" == "$OLD_PRIMARY_SHA256" ]] \
  || fail "rotation backup is not the previous encrypted primary"
stop_server

start_server "$OUTPUT_DIR/restart-new.log" "$NEW_KEY"
wait_ready "$OUTPUT_DIR/restart-new.log" || {
  tail -n 100 "$OUTPUT_DIR/restart-new.log" >&2
  fail "new-key-only restart failed"
}
[[ "$(sha256_file "$REGISTRY")" == "$NEW_PRIMARY_SHA256" ]] \
  || fail "new-key restart rewrote durable state"
stop_server

grep -aF "$TOKEN_HASH" \
  "$REGISTRY" \
  "$BACKUP" \
  "$OUTPUT_DIR/qkeys.downgraded" \
  "$OUTPUT_DIR/qkeys.good" \
  "$OUTPUT_DIR/qkeys.tampered" \
  "$OUTPUT_DIR"/*.log \
  "$OUTPUT_DIR"/*.cmdline >/dev/null 2>&1 \
  && fail "token hash leaked into retained encrypted or process evidence"
if find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.tmp-*' -print -quit | grep -q .; then
  fail "temporary registry file residue remains"
fi

{
  printf 'result=pass\n'
  printf 'binary_sha256=%s\n' "$BINARY_SHA256"
  printf 'old_primary_sha256=%s\n' "$OLD_PRIMARY_SHA256"
  printf 'new_primary_sha256=%s\n' "$NEW_PRIMARY_SHA256"
  printf 'backup_sha256=%s\n' "$(sha256_file "$BACKUP")"
  printf 'primary_mode=%s\n' "$(file_mode "$REGISTRY")"
  printf 'backup_mode=%s\n' "$(file_mode "$BACKUP")"
  printf 'plaintext_marker_leaks=0\n'
  printf 'master_key_argument_leaks=0\n'
  printf 'temporary_file_residue=0\n'
  printf 'owned_process_residue=0\n'
  printf 'plaintext_downgrade_rejections=1\n'
} >"$OUTPUT_DIR/summary.txt"

echo "PASS: QKey registry encryption process proof"
cat "$OUTPUT_DIR/summary.txt"
echo "evidence=$OUTPUT_DIR"
