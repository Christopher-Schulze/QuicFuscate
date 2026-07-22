#!/usr/bin/env bash
# Privileged kill-switch lifecycle proof in isolated Linux network namespaces.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CERT_DIR="$(mktemp -d /tmp/qf-killswitch-certs.XXXXXX)"
SERVER_NS="${SERVER_NS:-qf-ks-srv}"
CLIENT_NS="${CLIENT_NS:-qf-ks-cli}"
SERVER_UNDERLAY_IP="10.91.0.1"
CLIENT_UNDERLAY_IP="10.91.0.2"
SERVER_UNDERLAY_IP6="2001:db8:91::1"
CLIENT_UNDERLAY_IP6="2001:db8:91::2"
SERVER_TUN_IP="10.92.0.1"
CLIENT_TUN_IP="10.92.0.2"
LISTEN_PORT="4433"
HEARTBEAT_TIMEOUT_MS="${HEARTBEAT_TIMEOUT_MS:-500}"
TRANSITION_LIMIT_MS="$((HEARTBEAT_TIMEOUT_MS + 100))"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
SERVER_LOG="/tmp/qf-killswitch-server.log"
CLIENT_LOG="/tmp/qf-killswitch-client.log"
CAPTURE_FILE="/tmp/qf-killswitch-underlay.pcap"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

cleanup_runtime() {
  set +e
  [ -n "${CAPTURE_PID:-}" ] && kill "$CAPTURE_PID" 2>/dev/null
  [ -n "${CLIENT_PID:-}" ] && kill -9 "$CLIENT_PID" 2>/dev/null
  [ -n "${SERVER_PID:-}" ] && kill -9 "$SERVER_PID" 2>/dev/null
  ip netns del "$SERVER_NS" 2>/dev/null
  ip netns del "$CLIENT_NS" 2>/dev/null
}

cleanup() {
  cleanup_runtime
  rm -rf "$CERT_DIR"
}
trap cleanup EXIT

for command in flock ip nft openssl nc python3 dig ping tcpdump; do
  require_command "$command"
done
if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ ! -x "$BINARY" ]; then
  echo "missing executable: $BINARY" >&2
  exit 2
fi

exec 9>"$LOCK_FILE"
flock -w 300 9 || {
  echo "could not acquire $LOCK_FILE" >&2
  exit 2
}

wait_for() {
  local timeout_seconds="$1"
  shift
  local deadline=$((SECONDS + timeout_seconds))
  until "$@"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      return 1
    fi
    sleep 0.05
  done
}

process_exited() {
  ! kill -0 "$1" 2>/dev/null
}

rules_contain() {
  ip netns exec "$CLIENT_NS" nft list table inet quicfuscate_ks 2>/dev/null | grep -q -- "$1"
}

table_absent() {
  ! ip netns exec "$CLIENT_NS" nft list table inet quicfuscate_ks >/dev/null 2>&1
}

endpoint_rule_absent() {
  ! rules_contain "udp dport $LISTEN_PORT accept"
}

create_certificates() {
  mkdir -p "$CERT_DIR"
  if [ ! -s "$CERT_DIR/ca.crt" ] || [ ! -s "$CERT_DIR/ca.key" ]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/ca.key" \
      -out "$CERT_DIR/ca.crt" -days 2 -nodes -subj "/CN=QuicFuscate KillSwitch CA" \
      >/dev/null 2>&1
  fi
  openssl req -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
    -out /tmp/qf-killswitch-server.csr -nodes -subj "/CN=cdn.cloudflare.com" \
    >/dev/null 2>&1
  openssl x509 -req -in /tmp/qf-killswitch-server.csr \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out /tmp/qf-killswitch-leaf.crt -days 2 \
    -extfile <(printf '%s\n' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' \
      "subjectAltName=DNS:cdn.cloudflare.com,IP:$SERVER_UNDERLAY_IP") \
    >/dev/null 2>&1
  cp /tmp/qf-killswitch-leaf.crt "$CERT_DIR/server.crt"
  cat "$CERT_DIR/ca.crt" >> "$CERT_DIR/server.crt"
}

setup_namespaces() {
  cleanup_runtime
  set -e
  CLIENT_PID=""
  SERVER_PID=""
  ip netns add "$SERVER_NS"
  ip netns add "$CLIENT_NS"
  ip link add qf-ks-srv-veth type veth peer name qf-ks-cli-veth
  ip link set qf-ks-srv-veth netns "$SERVER_NS"
  ip link set qf-ks-cli-veth netns "$CLIENT_NS"
  ip netns exec "$SERVER_NS" ip address add "$SERVER_UNDERLAY_IP/24" dev qf-ks-srv-veth
  ip netns exec "$SERVER_NS" ip -6 address add "$SERVER_UNDERLAY_IP6/64" dev qf-ks-srv-veth
  ip netns exec "$CLIENT_NS" ip address add "$CLIENT_UNDERLAY_IP/24" dev qf-ks-cli-veth
  ip netns exec "$CLIENT_NS" ip -6 address add "$CLIENT_UNDERLAY_IP6/64" dev qf-ks-cli-veth
  ip netns exec "$SERVER_NS" ip link set lo up
  ip netns exec "$SERVER_NS" ip link set qf-ks-srv-veth up
  ip netns exec "$CLIENT_NS" ip link set lo up
  ip netns exec "$CLIENT_NS" ip link set qf-ks-cli-veth up
}

start_server() {
  rm -f /tmp/qf-killswitch-admin.sock "$SERVER_LOG"
  ip netns exec "$SERVER_NS" "$BINARY" server \
    --cert "$CERT_DIR/server.crt" --key "$CERT_DIR/server.key" \
    --listen "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
    --admin-socket /tmp/qf-killswitch-admin.sock \
    --tun --tun-name qtun0 --tun-ip "$SERVER_TUN_IP" \
    --tun-netmask 255.255.255.0 --no-drop-privileges -v \
    >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for 10 test -S /tmp/qf-killswitch-admin.sock
}

fetch_qkey() {
  printf '%s\n' '{"cmd":"qkey"}' | nc -U /tmp/qf-killswitch-admin.sock | \
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["qkey"])'
}

start_client() {
  local qkey="$1"
  rm -f "$CLIENT_LOG"
  ip netns exec "$CLIENT_NS" "$BINARY" client \
    --remote "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
    --url "https://$SERVER_UNDERLAY_IP/" --qkey "$qkey" \
    --ca-file "$CERT_DIR/ca.crt" --verify-peer --no-utls \
    --tun --tun-name qtun0 --tun-ip "$CLIENT_TUN_IP" \
    --tun-netmask 255.255.255.0 --kill-switch \
    --vpn-dns "$SERVER_TUN_IP" \
    --heartbeat-timeout-ms "$HEARTBEAT_TIMEOUT_MS" -v \
    >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID=$!
  wait_for 15 grep -q 'TLS handshake complete' "$CLIENT_LOG"
  wait_for 10 rules_contain 'oifname "qtun0" accept'
}

assert_connected_policy() {
  local rules
  rules="$(ip netns exec "$CLIENT_NS" nft list table inet quicfuscate_ks)"
  grep -q "ip daddr $SERVER_UNDERLAY_IP udp dport $LISTEN_PORT accept" <<<"$rules"
  grep -q "oifname \"qtun0\" ip daddr $SERVER_TUN_IP udp dport 53 accept" <<<"$rules"
  grep -q 'udp dport 53 drop' <<<"$rules"
  grep -q 'tcp dport 53 drop' <<<"$rules"
  grep -q 'oifname "qtun0" accept' <<<"$rules"
}

assert_dns_and_ipv6_policy() {
  ip netns exec "$CLIENT_NS" tcpdump -i qf-ks-cli-veth -nn -U \
    -w "$CAPTURE_FILE" '(port 53 or ip6)' >/dev/null 2>&1 &
  CAPTURE_PID=$!
  sleep 0.5

  ip netns exec "$CLIENT_NS" dig @"$SERVER_TUN_IP" example.com A \
    +tries=1 +time=5 +norecurse +stats >/tmp/qf-killswitch-vpn-dns.log
  if ip netns exec "$CLIENT_NS" dig @"$SERVER_UNDERLAY_IP" example.com A \
    +tries=1 +time=1 +norecurse >/tmp/qf-killswitch-direct-dns.log 2>&1; then
    echo "direct underlay DNS unexpectedly succeeded" >&2
    exit 1
  fi
  if ip netns exec "$CLIENT_NS" ping -6 -c 1 -W 1 "$SERVER_UNDERLAY_IP6" \
    >/tmp/qf-killswitch-ipv6.log 2>&1; then
    echo "direct IPv6 unexpectedly bypassed the kill switch" >&2
    exit 1
  fi

  kill "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""
  local leaked
  leaked="$(tcpdump -nn -r "$CAPTURE_FILE" 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$leaked" != "0" ]; then
    echo "underlay DNS/IPv6 leak detected: $leaked packets" >&2
    tcpdump -nn -r "$CAPTURE_FILE" >&2
    exit 1
  fi
}

assert_unexpected_loss_retains_block() {
  local start_ms end_ms elapsed_ms
  start_ms="$(date +%s%3N)"
  kill -9 "$SERVER_PID"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  wait_for 3 rules_contain 'policy drop'
  wait_for 3 endpoint_rule_absent
  end_ms="$(date +%s%3N)"
  elapsed_ms="$((end_ms - start_ms))"
  if [ "$elapsed_ms" -gt "$TRANSITION_LIMIT_MS" ]; then
    echo "fail-closed transition took ${elapsed_ms}ms, limit ${TRANSITION_LIMIT_MS}ms" >&2
    exit 1
  fi
  wait_for 5 process_exited "$CLIENT_PID"
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""
  rules_contain 'policy drop'
  if rules_contain 'oifname "qtun0" accept'; then
    echo "TUN allow rule survived unexpected loss" >&2
    exit 1
  fi
  if ip netns exec "$CLIENT_NS" ping -c 1 -W 1 "$SERVER_UNDERLAY_IP" >/dev/null 2>&1; then
    echo "underlay traffic escaped after unexpected loss" >&2
    exit 1
  fi
  echo "unexpected-loss transition: ${elapsed_ms}ms"
}

assert_stale_cleanup() {
  ip netns exec "$CLIENT_NS" "$BINARY" client \
    --remote "$SERVER_UNDERLAY_IP:$LISTEN_PORT" --cleanup-firewall >/dev/null 2>&1
  wait_for 5 table_absent
}

assert_clean_signal_cleanup() {
  start_server
  local qkey
  qkey="$(fetch_qkey)"
  start_client "$qkey"
  kill -TERM "$CLIENT_PID"
  wait_for 5 process_exited "$CLIENT_PID"
  wait "$CLIENT_PID"
  CLIENT_PID=""
  wait_for 5 table_absent
}

create_certificates
setup_namespaces
start_server
QKEY="$(fetch_qkey)"
start_client "$QKEY"
assert_connected_policy
assert_dns_and_ipv6_policy
assert_unexpected_loss_retains_block
assert_stale_cleanup
assert_clean_signal_cleanup

echo "PASS: connected DNS policy, IPv6 blocking, ${TRANSITION_LIMIT_MS}ms loss bound, retained fail-closed state, stale cleanup, and SIGTERM cleanup"
