#!/usr/bin/env bash
# End-to-end DNS leak test: two Linux network namespaces over a veth pair,
# QUIC tunnel with TUN/MASQUE, DNS query over the client TUN, tcpdump proof
# that no raw DNS (TCP/UDP port 53) leaves the client underlay interface.
#
# Acceptance criteria:
#   - Client and server complete the TLS handshake.
#   - A real DNS query sent to the server TUN IP receives a DNS response.
#   - tcpdump on the client veth underlay observes zero TCP/UDP port 53 packets.
#
# Requirements: root, Linux, iproute2, tcpdump, openssl, python3, nc, dig.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"
CA="$PROJECT_ROOT/config/local/ca.crt"
CERT_DIR="$PROJECT_ROOT/config/local"

SERVER_NS="${SERVER_NS:-ns-srv}"
CLIENT_NS="${CLIENT_NS:-ns-cli}"
SERVER_UNDERLAY_IP="${SERVER_UNDERLAY_IP:-10.10.0.1}"
CLIENT_UNDERLAY_IP="${CLIENT_UNDERLAY_IP:-10.10.0.2}"
SERVER_TUN_IP="${SERVER_TUN_IP:-10.0.1.1}"
CLIENT_TUN_IP="${CLIENT_TUN_IP:-10.0.1.2}"
LISTEN_PORT="${LISTEN_PORT:-4433}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"

TCPDUMP_LOG="/tmp/qf-dns-leak-tcpdump.log"
TCPDUMP_PCAP="/tmp/qf-dns-leak.pcap"
DNS_OUT="/tmp/qf-dns-leak-dig.out"
SERVER_LOG="/tmp/qf-dns-leak-server.log"
CLIENT_LOG="/tmp/qf-dns-leak-client.log"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

cleanup() {
  set +e
  [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null
  pkill -9 -f "$B" 2>/dev/null
  ip netns del "$SERVER_NS" 2>/dev/null
  ip netns del "$CLIENT_NS" 2>/dev/null
}
trap cleanup EXIT

for cmd in ip tcpdump openssl python3 nc dig; do
  require_cmd "$cmd"
done
require_cmd flock

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
  echo "could not acquire TUN E2E lock $LOCK_FILE within ${LOCK_TIMEOUT}s" >&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ ! -x "$B" ]; then
  echo "missing executable: $B" >&2
  exit 2
fi

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"
cat > /tmp/qf-dns-leaf-ext.cnf <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:$SERVER_UNDERLAY_IP
EOF
if [ ! -s ca.crt ] || [ ! -s ca.key ]; then
  openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 365 \
    -nodes -subj "/CN=QuicFuscate Test CA" 2>/dev/null
fi
openssl req -newkey rsa:2048 -keyout server.key -out /tmp/qf-dns-server.csr \
  -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null
openssl x509 -req -in /tmp/qf-dns-server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out /tmp/qf-dns-leaf.crt -days 365 \
  -extfile /tmp/qf-dns-leaf-ext.cnf 2>/dev/null
cat /tmp/qf-dns-leaf.crt ca.crt > server.crt
chmod 600 server.key ca.key 2>/dev/null || true
cd "$PROJECT_ROOT"

cleanup
rm -f "$TCPDUMP_LOG" "$TCPDUMP_PCAP" "$DNS_OUT" "$SERVER_LOG" "$CLIENT_LOG"

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add veth-srv type veth peer name veth-cli
ip link set veth-srv netns "$SERVER_NS"
ip link set veth-cli netns "$CLIENT_NS"
ip netns exec "$SERVER_NS" ip addr add "$SERVER_UNDERLAY_IP/24" dev veth-srv
ip netns exec "$SERVER_NS" ip link set veth-srv up
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_UNDERLAY_IP/24" dev veth-cli
ip netns exec "$CLIENT_NS" ip link set veth-cli up
ip netns exec "$CLIENT_NS" ip link set lo up
for ns in "$SERVER_NS" "$CLIENT_NS"; do
  ip netns exec "$ns" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
  ip netns exec "$ns" sysctl -wq net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
done

echo "=== underlay connectivity ==="
ip netns exec "$CLIENT_NS" ping -c1 -W2 "$SERVER_UNDERLAY_IP" 2>&1 | grep -E "bytes from|packet loss"

ip netns exec "$SERVER_NS" "$B" server --cert "$CERT" --key "$KEY" \
  --listen "$SERVER_UNDERLAY_IP:$LISTEN_PORT" --admin-socket /tmp/qf-dns-admin.sock \
  --tun --tun-name qtun0 --tun-ip "$SERVER_TUN_IP" --tun-netmask 255.255.255.0 \
  --no-drop-privileges -v \
  > "$SERVER_LOG" 2>&1 &
sleep 3

QKEY=$(echo '{"cmd":"qkey"}' | nc -U /tmp/qf-dns-admin.sock 2>/dev/null | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])')
echo "qkey len: ${#QKEY}"

ip netns exec "$CLIENT_NS" "$B" client --remote "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
  --url "https://$SERVER_UNDERLAY_IP/" --qkey "$QKEY" --ca-file "$CA" --verify-peer \
  --tun --tun-name qtun0 --tun-ip "$CLIENT_TUN_IP" --tun-netmask 255.255.255.0 --no-utls -v \
  > "$CLIENT_LOG" 2>&1 &
sleep 5

ip netns exec "$SERVER_NS" ip addr add "$SERVER_TUN_IP/24" dev qtun0 2>/dev/null || true
ip netns exec "$SERVER_NS" ip link set qtun0 up 2>/dev/null || true
ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_TUN_IP/24" dev qtun0 2>/dev/null || true
ip netns exec "$CLIENT_NS" ip link set qtun0 up 2>/dev/null || true
sleep 2

echo "=== tunnel status ==="
echo "srv: $(ip netns exec "$SERVER_NS" ip -br addr show qtun0 2>&1)"
echo "cli: $(ip netns exec "$CLIENT_NS" ip -br addr show qtun0 2>&1)"
echo "client_complete=$(grep -c 'TLS handshake complete' "$CLIENT_LOG") server_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG")"

ip netns exec "$CLIENT_NS" tcpdump -i veth-cli -nn -U -w "$TCPDUMP_PCAP" \
  '(udp port 53 or tcp port 53)' > "$TCPDUMP_LOG" 2>&1 &
TCPDUMP_PID=$!
sleep 1

set +e
ip netns exec "$CLIENT_NS" dig @"$SERVER_TUN_IP" example.com A +tries=1 +time=5 +norecurse +stats > "$DNS_OUT" 2>&1
DIG_STATUS=$?
set -e
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

DNS_STATUS_LINE="$(grep -m1 'status:' "$DNS_OUT" || true)"
LEAK_COUNT="$(tcpdump -nn -r "$TCPDUMP_PCAP" 2>/dev/null | wc -l | tr -d ' ')"

echo "=== DNS result ==="
echo "dig_exit=$DIG_STATUS"
echo "$DNS_STATUS_LINE"
echo "=== underlay tcpdump ==="
echo "raw_port_53_packets=$LEAK_COUNT"

if [ "$DIG_STATUS" -ne 0 ]; then
  echo "DNS query failed" >&2
  cat "$DNS_OUT" >&2
  exit 1
fi
if ! grep -q 'status:' "$DNS_OUT"; then
  echo "DNS response missing status line" >&2
  cat "$DNS_OUT" >&2
  exit 1
fi
if [ "$LEAK_COUNT" != "0" ]; then
  echo "DNS leak detected: raw port 53 observed on client underlay" >&2
  tcpdump -nn -r "$TCPDUMP_PCAP" 2>/dev/null >&2 || true
  exit 1
fi

echo "PASS: DNS response received and zero raw port 53 packets observed on client underlay"
