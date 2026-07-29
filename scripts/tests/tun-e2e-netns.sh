#!/usr/bin/env bash
# End-to-end VPN data-plane test: two network namespaces over a veth pair,
# QUIC tunnel with TUN, ping through the tunnel via MASQUE CONNECT-UDP.
#
# Acceptance criteria (TODO-422):
#   - ip netns exec ns-cli ping -c5 10.0.1.1  -> 0% packet loss
#   - Both sides log "TLS handshake complete"; no panics
#   - MASQUE_BYTES_RECEIVED counters increment on both ends
#
# Requirements: root, Linux, iproute2, procps, openssl, python3, nc (openbsd-netcat).
# Run on the target server (e.g. broderick). Single-host loopback short-circuits
# TUN routing, so netns + veth is mandatory.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CERT_SOURCE_DIR="$PROJECT_ROOT/config/local"
CERT_DIR=""
CERT=""
KEY=""
CA=""
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
STARTUP_TIMEOUT="${QF_E2E_STARTUP_TIMEOUT:-15}"
QKEY_STORE="${QF_E2E_QKEY_STORE:-/tmp/qf-tun-e2e-qkeys.json}"
ADMIN_SOCKET="${QF_E2E_ADMIN_SOCKET:-/tmp/qf-tun-e2e-admin.sock}"
SERVER_CONFIG_ARGS=()
CLIENT_CONFIG_ARGS=()
SERVER_PRIVILEGE_ARGS=(--no-drop-privileges)
SERVER_PID=""
CLIENT_PID=""
NAMESPACES_CREATED=0
if [ -n "${QF_E2E_SERVER_CONFIG:-}" ]; then
  SERVER_CONFIG_ARGS=(--config "$QF_E2E_SERVER_CONFIG")
fi
if [ -n "${QF_E2E_CLIENT_CONFIG:-}" ]; then
  CLIENT_CONFIG_ARGS=(--config "$QF_E2E_CLIENT_CONFIG")
fi
if [ "${QF_E2E_DROP_PRIVILEGES:-0}" = "1" ]; then
  SERVER_PRIVILEGE_ARGS=(
    --drop-user "${QF_E2E_DROP_USER:-nobody}"
    --drop-group "${QF_E2E_DROP_GROUP:-nogroup}"
  )
fi

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
  echo "FAIL: could not acquire TUN E2E lock $LOCK_FILE within ${LOCK_TIMEOUT}s" >&2
  exit 2
fi

stop_owned_process() {
  local pid="$1"
  if [ -z "$pid" ]; then
    return
  fi

  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  stop_owned_process "$CLIENT_PID"
  CLIENT_PID=""
  stop_owned_process "$SERVER_PID"
  SERVER_PID=""

  if [ "$NAMESPACES_CREATED" = "1" ]; then
    ip netns del ns-srv 2>/dev/null
    ip netns del ns-cli 2>/dev/null
    NAMESPACES_CREATED=0
  fi
  rm -f "$QKEY_STORE"
  rm -f "$ADMIN_SOCKET"
  if [ -n "$CERT_DIR" ] && [ -d "$CERT_DIR" ]; then
    rm -rf "$CERT_DIR"
    CERT_DIR=""
  fi
}

# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup_on_exit() {
  if [ "$KEEP_ON_FAIL" != "1" ]; then
    cleanup
  fi
}

dump_diagnostics() {
  echo "=== failure diagnostics: TUN link counters ===" >&2
  ip netns exec ns-srv ip -s link show qtun0 >&2 2>/dev/null || true
  ip netns exec ns-cli ip -s link show qtun0 >&2 2>/dev/null || true
  echo "=== failure diagnostics: server MASQUE/TUN/errors ===" >&2
  grep -iE "tun|error|warn|panic|MASQUE|datagram|ICMP" /tmp/ns-srv.log 2>/dev/null | \
    grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache|stats:" | tail -80 >&2 || true
  echo "=== failure diagnostics: client MASQUE/TUN/errors ===" >&2
  grep -iE "tun|error|warn|panic|MASQUE|datagram|ICMP" /tmp/ns-cli.log 2>/dev/null | \
    grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache|stats:" | tail -80 >&2 || true
}

fail() {
  echo "FAIL: $*" >&2
  dump_diagnostics
  if [ "$KEEP_ON_FAIL" = "1" ]; then
    echo "QF_E2E_KEEP_ON_FAIL=1: leaving namespaces and processes alive for inspection" >&2
  fi
  exit 1
}

# --- fail closed before touching certificates or runtime resources ---
if pgrep -x quicfuscate >/dev/null; then
  echo "FAIL: a pre-existing quicfuscate process is running; refusing broad cleanup" >&2
  exit 2
fi
if ip netns list | grep -Eq '^(ns-srv|ns-cli)([[:space:]]|$)'; then
  echo "FAIL: ns-srv or ns-cli already exists; refusing to delete an unowned namespace" >&2
  exit 2
fi
if [ -e "$ADMIN_SOCKET" ]; then
  echo "FAIL: admin socket path already exists; refusing to remove unowned path $ADMIN_SOCKET" >&2
  exit 2
fi
trap cleanup_on_exit EXIT

# --- ensure server cert valid for the client's hardcoded validation SNI ---
CERT_DIR="$(mktemp -d /tmp/quicfuscate-tun-cert.XXXXXX)"
CERT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"
CA="$CERT_DIR/ca.crt"
cp "$CERT_SOURCE_DIR/ca.crt" "$CA"
cp "$CERT_SOURCE_DIR/ca.key" "$CERT_DIR/ca.key"
cd "$CERT_DIR" || fail "could not enter certificate directory"
cat > /tmp/leaf-ext.cnf <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:10.10.0.1
EOF
openssl req -newkey rsa:2048 -keyout server.key -out /tmp/s.csr -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null
openssl x509 -req -in /tmp/s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out /tmp/leaf.crt -days 365 -extfile /tmp/leaf-ext.cnf 2>/dev/null
cat /tmp/leaf.crt ca.crt > server.crt
cd "$PROJECT_ROOT" || fail "could not return to project root"

# --- netns + veth ---
ip netns add ns-srv
NAMESPACES_CREATED=1
ip netns add ns-cli
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns ns-srv
ip link set veth-cli netns ns-cli
ip netns exec ns-srv ip addr add 10.10.0.1/24 dev veth-srv
ip netns exec ns-srv ip link set veth-srv up
ip netns exec ns-srv ip link set lo up
ip netns exec ns-srv ip route add default dev veth-srv
ip netns exec ns-cli ip addr add 10.10.0.2/24 dev veth-cli
ip netns exec ns-cli ip link set veth-cli up
ip netns exec ns-cli ip link set lo up
for ns in ns-srv ns-cli; do
  ip netns exec "$ns" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null
  ip netns exec "$ns" sysctl -wq net.ipv4.conf.default.rp_filter=0 2>/dev/null
done

echo "=== veth connectivity (cli -> srv) ==="
ip netns exec ns-cli ping -c1 -W2 10.10.0.1 2>&1 | grep -E "bytes from|packet loss"

# --- start server in ns-srv ---
ip netns exec ns-srv "$B" server --cert "$CERT" --key "$KEY" \
  --listen 10.10.0.1:4433 --admin-socket "$ADMIN_SOCKET" \
  --qkey-store "$QKEY_STORE" \
  --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
  "${SERVER_PRIVILEGE_ARGS[@]}" -v "${SERVER_CONFIG_ARGS[@]}" \
  > /tmp/ns-srv.log 2>&1 &
SERVER_PID=$!

QKEY=""
for ((attempt = 0; attempt < STARTUP_TIMEOUT; attempt++)); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    break
  fi
  if [ -S "$ADMIN_SOCKET" ]; then
    QKEY=$(echo '{"cmd":"qkey"}' | nc -w 1 -U "$ADMIN_SOCKET" 2>/dev/null | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)
    if [ -n "$QKEY" ]; then
      break
    fi
  fi
  sleep 1
done
echo "qkey len: ${#QKEY}"
if [ -z "$QKEY" ]; then
  cat /tmp/ns-srv.log >&2
  fail "could not issue QKey from admin socket"
fi

# --- start client in ns-cli ---
ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
  --qkey "$QKEY" --ca-file "$CA" --verify-peer \
  --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 --no-utls -v \
  "${CLIENT_CONFIG_ARGS[@]}" \
  > /tmp/ns-cli.log 2>&1 &
CLIENT_PID=$!
sleep 4

# --- ensure TUN up + ip + route in each netns ---
ip netns exec ns-srv ip addr add 10.0.1.1/24 dev qtun0 2>/dev/null
ip netns exec ns-srv ip link set qtun0 up 2>/dev/null
ip netns exec ns-cli ip addr add 10.0.1.2/24 dev qtun0 2>/dev/null
ip netns exec ns-cli ip link set qtun0 up 2>/dev/null
sleep 2

echo "=== TUN ifaces ==="
echo "srv: $(ip netns exec ns-srv ip -br addr show qtun0 2>&1)"
echo "cli: $(ip netns exec ns-cli ip -br addr show qtun0 2>&1)"
echo "=== handshake status ==="
echo "client_complete=$(grep -c 'TLS handshake complete' /tmp/ns-cli.log) server_complete=$(grep -c 'TLS handshake complete' /tmp/ns-srv.log)"
if [ "$(grep -c 'TLS handshake complete' /tmp/ns-cli.log)" = "0" ] || [ "$(grep -c 'TLS handshake complete' /tmp/ns-srv.log)" = "0" ]; then
  cat /tmp/ns-srv.log >&2
  cat /tmp/ns-cli.log >&2
  fail "TLS handshake did not complete on both sides"
fi

echo "=== PING THROUGH TUNNEL (cli 10.0.1.2 -> srv 10.0.1.1) ==="
CLIENT_TO_SERVER_PING="$(ip netns exec ns-cli ping -c 5 -W 3 -I qtun0 10.0.1.1 2>&1)"
echo "$CLIENT_TO_SERVER_PING" | tail -7
if ! echo "$CLIENT_TO_SERVER_PING" | grep -q " 0% packet loss"; then
  fail "client-to-server ping through tunnel did not achieve 0% packet loss"
fi

echo "=== PING THROUGH TUNNEL (srv 10.0.1.1 -> cli 10.0.1.2) ==="
SERVER_TO_CLIENT_PING="$(ip netns exec ns-srv ping -c 5 -W 3 -I qtun0 10.0.1.2 2>&1)"
echo "$SERVER_TO_CLIENT_PING" | tail -7
if ! echo "$SERVER_TO_CLIENT_PING" | grep -q " 0% packet loss"; then
  fail "server-to-client ping through tunnel did not achieve 0% packet loss"
fi

echo "=== MASQUE counters ==="
echo "srv: $(grep -i 'MASQUE' /tmp/ns-srv.log | tail -3)"
echo "cli: $(grep -i 'MASQUE' /tmp/ns-cli.log | tail -3)"

echo "=== server log tail (TUN/errors) ==="
grep -iE "tun|error|warn|panic|MASQUE" /tmp/ns-srv.log | grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache" | tail -10
echo "=== client log tail (TUN/errors) ==="
grep -iE "tun|error|warn|panic|MASQUE" /tmp/ns-cli.log | grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache" | tail -10

# cleanup
cleanup
trap - EXIT
exit 0
