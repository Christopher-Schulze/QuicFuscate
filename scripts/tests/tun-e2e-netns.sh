#!/usr/bin/env bash
# End-to-end VPN data-plane test: two network namespaces over a veth pair,
# QUIC tunnel with TUN, ping through the tunnel via MASQUE CONNECT-UDP.
#
# Acceptance criteria (TODO-422):
#   - ip netns exec ns-cli ping -c5 10.0.1.1  -> 0% packet loss
#   - Both sides log "TLS handshake complete"; no panics
#   - MASQUE_BYTES_RECEIVED counters increment on both ends
#
# Requirements: root, Linux, iproute2, openssl, python3, nc (openbsd-netcat).
# Run on the target server (e.g. broderick). Single-host loopback short-circuits
# TUN routing, so netns + veth is mandatory.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="$PROJECT_ROOT/target/release/quicfuscate"
CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"
CA="$PROJECT_ROOT/config/local/ca.crt"
CERT_DIR="$PROJECT_ROOT/config/local"
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
SERVER_CONFIG_ARGS=()
CLIENT_CONFIG_ARGS=()
if [ -n "${QF_E2E_SERVER_CONFIG:-}" ]; then
  SERVER_CONFIG_ARGS=(--config "$QF_E2E_SERVER_CONFIG")
fi
if [ -n "${QF_E2E_CLIENT_CONFIG:-}" ]; then
  CLIENT_CONFIG_ARGS=(--config "$QF_E2E_CLIENT_CONFIG")
fi

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
  echo "FAIL: could not acquire TUN E2E lock $LOCK_FILE within ${LOCK_TIMEOUT}s" >&2
  exit 2
fi

cleanup() {
  pkill -9 -f quicfuscate 2>/dev/null
  ip netns del ns-srv 2>/dev/null
  ip netns del ns-cli 2>/dev/null
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
  else
    cleanup
  fi
  exit 1
}

# --- ensure server cert valid for the client's hardcoded validation SNI ---
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

# --- cleanup ---
cleanup
sleep 1

# --- netns + veth ---
ip netns add ns-srv
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
  --listen 10.10.0.1:4433 --admin-socket /tmp/qf-admin.sock \
  --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
  --no-drop-privileges -v "${SERVER_CONFIG_ARGS[@]}" \
  > /tmp/ns-srv.log 2>&1 &
sleep 3

QKEY=$(echo '{"cmd":"qkey"}' | nc -U /tmp/qf-admin.sock 2>/dev/null | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)
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
PING_OUTPUT="$(ip netns exec ns-cli ping -c 5 -W 3 -I qtun0 10.0.1.1 2>&1)"
echo "$PING_OUTPUT" | tail -7
if ! echo "$PING_OUTPUT" | grep -q " 0% packet loss"; then
  fail "ping through tunnel did not achieve 0% packet loss"
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
exit 0
