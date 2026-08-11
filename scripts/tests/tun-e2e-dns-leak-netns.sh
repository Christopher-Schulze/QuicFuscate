#!/usr/bin/env bash
# End-to-end DNS leak test: two Linux network namespaces over a veth pair,
# QUIC tunnel with TUN/MASQUE, explicit and OS-resolver DNS queries, and
# tcpdump proof that no raw DNS (TCP/UDP port 53) leaves the client underlay.
# The client resolver runs in a private mount namespace so the host resolver
# configuration is never modified by the Linux platform backend.
#
# Acceptance criteria:
#   - Client and server complete the TLS handshake.
#   - A real DNS query sent explicitly to the server TUN IP receives a DNS response.
#   - A normal OS resolver query reaches the client-owned localhost proxy.
#   - tcpdump on the client veth underlay observes zero TCP/UDP port 53 packets.
#   - Only exact child PIDs and resources created by this run are cleaned.
#   - Binary identity, logs, DNS output, and capture evidence use one new artifact path.
#
# Requirements: root, Linux, iproute2, tcpdump, openssl, python3, nc, dig,
# nsenter, unshare, mount.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="${QF_E2E_CA:-$PROJECT_ROOT/config/local/ca.crt}"
CA_KEY="${QF_E2E_CA_KEY:-$PROJECT_ROOT/config/local/ca.key}"
CERT=""
KEY=""

SERVER_NS="${SERVER_NS:-ns-srv}"
CLIENT_NS="${CLIENT_NS:-ns-cli}"
SERVER_UNDERLAY_IP="${SERVER_UNDERLAY_IP:-10.10.0.1}"
CLIENT_UNDERLAY_IP="${CLIENT_UNDERLAY_IP:-10.10.0.2}"
SERVER_TUN_IP="${SERVER_TUN_IP:-10.0.1.1}"
CLIENT_TUN_IP="${CLIENT_TUN_IP:-10.0.1.2}"
LISTEN_PORT="${LISTEN_PORT:-4433}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-dns-leak-evidence-$$}"
RUNTIME_DIR=""
ADMIN_SOCKET=""
SERVER_PID=""
CLIENT_PID=""
TCPDUMP_PID=""
SERVER_NAMESPACE_CREATED=0
CLIENT_NAMESPACE_CREATED=0
VETH_CREATED=0

TCPDUMP_LOG=""
TCPDUMP_PCAP=""
DNS_OUT=""
DNS_OS_OUT=""
PRIVATE_RESOLV_CONF=""
PRIVATE_RESOLVE_DIR=""
DOH_PROVIDER="${QF_E2E_DOH_PROVIDER:-https://127.0.0.1:1/dns-query}"
SERVER_LOG=""
CLIENT_LOG=""

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq -- "$1"
}

stop_owned_process() {
  local pid="$1"
  [ -n "$pid" ] || return
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..50}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
  ! kill -0 "$pid" 2>/dev/null
}

cleanup_owned_resources() {
  local cleanup_failed=0
  stop_owned_process "$TCPDUMP_PID" || cleanup_failed=1
  TCPDUMP_PID=""
  stop_owned_process "$CLIENT_PID" || cleanup_failed=1
  CLIENT_PID=""
  stop_owned_process "$SERVER_PID" || cleanup_failed=1
  SERVER_PID=""
  if [ "$CLIENT_NAMESPACE_CREATED" = "1" ]; then
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    if namespace_exists "$CLIENT_NS"; then
      cleanup_failed=1
    else
      CLIENT_NAMESPACE_CREATED=0
    fi
  fi
  if [ "$SERVER_NAMESPACE_CREATED" = "1" ]; then
    ip netns del "$SERVER_NS" 2>/dev/null || true
    if namespace_exists "$SERVER_NS"; then
      cleanup_failed=1
    else
      SERVER_NAMESPACE_CREATED=0
    fi
  fi
  if [ "$VETH_CREATED" = "1" ]; then
    ip link del veth-srv 2>/dev/null || ip link del veth-cli 2>/dev/null || true
    if ip link show dev veth-srv >/dev/null 2>&1 || \
      ip link show dev veth-cli >/dev/null 2>&1; then
      cleanup_failed=1
    else
      VETH_CREATED=0
    fi
  fi
  return "$cleanup_failed"
}

remove_runtime_dir() {
  [ -n "$RUNTIME_DIR" ] || return
  case "$RUNTIME_DIR" in
    /tmp/quicfuscate-dns-leak.*) rm -rf -- "$RUNTIME_DIR" ;;
    *) echo "refusing to remove unexpected runtime path: $RUNTIME_DIR" >&2; return 1 ;;
  esac
  RUNTIME_DIR=""
}

require_runtime_owned_tun_assignment() {
  local namespace="$1"
  local expected_ipv4="$2"
  if ! ip netns exec "$namespace" ip -j addr show dev qtun0 | python3 -c \
    'import json,sys; expected=sys.argv[1]; data=json.load(sys.stdin); assert len(data)==1,data; link=data[0]; addresses={(item["family"],item["local"],item["prefixlen"]) for item in link["addr_info"]}; assert ("inet",expected,24) in addresses,(expected,addresses); assert "UP" in link["flags"],link' \
    "$expected_ipv4"; then
    echo "runtime-owned TUN assignment is incomplete in $namespace" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  cleanup_owned_resources
  remove_runtime_dir
}
trap cleanup EXIT

for cmd in ip tcpdump openssl python3 nc dig nsenter unshare mount sha256sum sysctl; do
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
if [ ! -r "$CA" ] || [ ! -r "$CA_KEY" ]; then
  echo "CA certificate or key fixture is unreadable" >&2
  exit 2
fi
if [ "${ARTIFACT_DIR#/}" = "$ARTIFACT_DIR" ]; then
  echo "QF_E2E_ARTIFACT_DIR must be an absolute path" >&2
  exit 2
fi
if [ -e "$ARTIFACT_DIR" ]; then
  echo "refusing to replace existing artifact path: $ARTIFACT_DIR" >&2
  exit 2
fi
if [ ! -d "$(dirname "$ARTIFACT_DIR")" ]; then
  echo "artifact parent directory does not exist: $(dirname "$ARTIFACT_DIR")" >&2
  exit 2
fi
if namespace_exists "$SERVER_NS" || namespace_exists "$CLIENT_NS"; then
  echo "server or client namespace already exists; refusing unowned cleanup" >&2
  exit 2
fi
if ip link show dev veth-srv >/dev/null 2>&1 || ip link show dev veth-cli >/dev/null 2>&1; then
  echo "server or client veth already exists; refusing unowned cleanup" >&2
  exit 2
fi

mkdir "$ARTIFACT_DIR"
RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-dns-leak.XXXXXX)"
ADMIN_SOCKET="$RUNTIME_DIR/admin.sock"
CERT="$RUNTIME_DIR/server.crt"
KEY="$RUNTIME_DIR/server.key"
TCPDUMP_LOG="$ARTIFACT_DIR/tcpdump.log"
TCPDUMP_PCAP="$ARTIFACT_DIR/underlay.pcap"
DNS_OUT="$ARTIFACT_DIR/explicit-dns.txt"
DNS_OS_OUT="$ARTIFACT_DIR/os-resolver-dns.txt"
PRIVATE_RESOLV_CONF="$RUNTIME_DIR/resolv.conf"
PRIVATE_RESOLVE_DIR="$RUNTIME_DIR/systemd-resolve"
SERVER_LOG="$ARTIFACT_DIR/server.log"
CLIENT_LOG="$ARTIFACT_DIR/client.log"
mkdir "$PRIVATE_RESOLVE_DIR"
sha256sum "$B" >"$ARTIFACT_DIR/binary.sha256"

CERT_EXT="$RUNTIME_DIR/leaf-ext.cnf"
CSR="$RUNTIME_DIR/server.csr"
LEAF_CERT="$RUNTIME_DIR/leaf.crt"
CA_SERIAL="$RUNTIME_DIR/ca.srl"
cat > "$CERT_EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:$SERVER_UNDERLAY_IP
EOF
openssl req -newkey rsa:2048 -keyout "$KEY" -out "$CSR" \
  -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null
openssl x509 -req -in "$CSR" -CA "$CA" -CAkey "$CA_KEY" \
  -CAserial "$CA_SERIAL" -CAcreateserial -out "$LEAF_CERT" -days 365 \
  -extfile "$CERT_EXT" 2>/dev/null
cat "$LEAF_CERT" "$CA" > "$CERT"
chmod 600 "$KEY"

printf 'nameserver 127.0.0.1\n' > "$PRIVATE_RESOLV_CONF"

ip netns add "$SERVER_NS"
SERVER_NAMESPACE_CREATED=1
ip netns add "$CLIENT_NS"
CLIENT_NAMESPACE_CREATED=1
ip link add veth-srv type veth peer name veth-cli
VETH_CREATED=1
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
  --listen "$SERVER_UNDERLAY_IP:$LISTEN_PORT" --admin-socket "$ADMIN_SOCKET" \
  --tun --tun-name qtun0 --tun-ip "$SERVER_TUN_IP" --tun-netmask 255.255.255.0 \
  --no-drop-privileges -v \
  > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 3

QKEY=$(echo '{"cmd":"qkey"}' | nc -U "$ADMIN_SOCKET" 2>/dev/null | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])')
echo "qkey len: ${#QKEY}"

ip netns exec "$CLIENT_NS" unshare --mount --propagation private \
  bash -c 'if [ -d /run/systemd/resolve ]; then mount --bind "$1" /run/systemd/resolve || exit 1; fi; mount --bind "$2" /etc/resolv.conf && shift 2 && exec "$@"' \
  qf-dns-client "$PRIVATE_RESOLVE_DIR" "$PRIVATE_RESOLV_CONF" "$B" client \
  --remote "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
  --url "https://$SERVER_UNDERLAY_IP/" --qkey "$QKEY" --ca-file "$CA" --verify-peer \
  --doh-provider "$DOH_PROVIDER" \
  --tun --tun-name qtun0 \
  --no-utls -v \
  > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
sleep 5

require_runtime_owned_tun_assignment "$SERVER_NS" "$SERVER_TUN_IP"
require_runtime_owned_tun_assignment "$CLIENT_NS" "$CLIENT_TUN_IP"

echo "=== tunnel status ==="
echo "srv: $(ip netns exec "$SERVER_NS" ip -br addr show qtun0 2>&1)"
echo "cli: $(ip netns exec "$CLIENT_NS" ip -br addr show qtun0 2>&1)"
echo "client_complete=$(grep -c 'TLS handshake complete' "$CLIENT_LOG") server_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG")"
if ! grep -q 'Client DoH DNS proxy active' "$CLIENT_LOG"; then
  echo "client DoH DNS proxy did not activate" >&2
  cat "$CLIENT_LOG" >&2
  exit 1
fi

ip netns exec "$CLIENT_NS" tcpdump -i veth-cli -nn -U -w "$TCPDUMP_PCAP" \
  '(udp port 53 or tcp port 53)' > "$TCPDUMP_LOG" 2>&1 &
TCPDUMP_PID=$!
sleep 1

set +e
ip netns exec "$CLIENT_NS" dig @"$SERVER_TUN_IP" example.com A +tries=1 +time=5 +norecurse +stats > "$DNS_OUT" 2>&1
DIG_STATUS=$?
ip netns exec "$CLIENT_NS" nsenter -t "$CLIENT_PID" -m -n -- \
  dig example.com A +tries=1 +time=5 +norecurse +stats > "$DNS_OS_OUT" 2>&1
OS_DIG_STATUS=$?
set -e
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

DNS_STATUS_LINE="$(grep -m1 'status:' "$DNS_OUT" || true)"
OS_DNS_STATUS_LINE="$(grep -m1 'status:' "$DNS_OS_OUT" || true)"
LEAK_COUNT="$(tcpdump -nn -r "$TCPDUMP_PCAP" 2>/dev/null | wc -l | tr -d ' ')"

echo "=== DNS result ==="
echo "dig_exit=$DIG_STATUS"
echo "$DNS_STATUS_LINE"
echo "os_dig_exit=$OS_DIG_STATUS"
echo "$OS_DNS_STATUS_LINE"
echo "=== underlay tcpdump ==="
echo "raw_port_53_packets=$LEAK_COUNT"

if [ "$DIG_STATUS" -ne 0 ] || [ "$OS_DIG_STATUS" -ne 0 ]; then
  echo "DNS query failed" >&2
  cat "$DNS_OUT" >&2
  cat "$DNS_OS_OUT" >&2
  exit 1
fi
if ! grep -q 'status:' "$DNS_OUT" || ! grep -q 'status:' "$DNS_OS_OUT"; then
  echo "DNS response missing status line" >&2
  cat "$DNS_OUT" >&2
  cat "$DNS_OS_OUT" >&2
  exit 1
fi
if [ "$LEAK_COUNT" != "0" ]; then
  echo "DNS leak detected: raw port 53 observed on client underlay" >&2
  tcpdump -nn -r "$TCPDUMP_PCAP" 2>/dev/null >&2 || true
  exit 1
fi

stop_owned_process "$CLIENT_PID"
CLIENT_PID=""
if ! grep -q 'Client DoH DNS proxy stopped and system DNS restored' "$CLIENT_LOG"; then
  echo "client DoH DNS proxy did not report resolver restoration" >&2
  cat "$CLIENT_LOG" >&2
  exit 1
fi

stop_owned_process "$SERVER_PID"
SERVER_PID=""
cleanup_owned_resources
remove_runtime_dir
trap - EXIT

echo "PASS: explicit and OS-resolver DNS responses received, resolver restored, zero raw port 53 packets observed on the client underlay, and evidence retained in $ARTIFACT_DIR"
