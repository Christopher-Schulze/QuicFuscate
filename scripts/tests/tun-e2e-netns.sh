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
CA_SOURCE="${QF_E2E_CA:-$PROJECT_ROOT/config/local/ca.crt}"
CA_KEY_SOURCE="${QF_E2E_CA_KEY:-$PROJECT_ROOT/config/local/ca.key}"
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
RESTART_ADMIN_SOCKET="${QF_E2E_RESTART_ADMIN_SOCKET:-${ADMIN_SOCKET}.restart}"
ROUTING_STATE_PATH="/run/quicfuscate/routing/7174756e30.json"
FIREWALL_OWNER_PATH="/run/quicfuscate/routing/firewall-owner.json"
SERVER_CONFIG_ARGS=()
CLIENT_CONFIG_ARGS=()
SERVER_PROFILE_ARGS=()
SERVER_PRIVILEGE_ARGS=(--no-drop-privileges)
SERVER_PID=""
SERVER_LOG_PATH=""
CLIENT_PID=""
CAPTURE_PID=""
NAMESPACES_CREATED=0
TRAFFIC_CAPTURE_FILE="${QF_E2E_TRAFFIC_CAPTURE_FILE:-}"
TRAFFIC_CAPTURE_SECONDS="${QF_E2E_TRAFFIC_CAPTURE_SECONDS:-10}"
TRAFFIC_CAPTURE_DRAIN_SECONDS=1
READY_HOOK="${QF_E2E_READY_HOOK:-}"
INITIAL_IPV4_FORWARDING=""
INITIAL_IPV6_FORWARDING=""
FIREWALL_BACKEND=""
if [ -n "${QF_E2E_SERVER_CONFIG:-}" ]; then
  SERVER_CONFIG_ARGS=(--config "$QF_E2E_SERVER_CONFIG")
fi
if [ -n "${QF_E2E_CLIENT_CONFIG:-}" ]; then
  CLIENT_CONFIG_ARGS=(--config "$QF_E2E_CLIENT_CONFIG")
fi
if [ -n "${QF_E2E_SERVER_PROFILE:-}" ]; then
  SERVER_PROFILE_ARGS+=(--profile "$QF_E2E_SERVER_PROFILE")
fi
if [ -n "${QF_E2E_SERVER_OS:-}" ]; then
  SERVER_PROFILE_ARGS+=(--os "$QF_E2E_SERVER_OS")
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

stop_owned_process_gracefully() {
  local pid="$1"
  local state=""
  if [ -z "$pid" ]; then
    return 0
  fi

  kill -TERM "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$state" == Z* ]] && break
    sleep 1
  done
  if kill -0 "$pid" 2>/dev/null && [[ "$state" != Z* ]]; then
    return 1
  fi
  wait "$pid" 2>/dev/null || true
}

stop_capture_process() {
  if [ -z "$CAPTURE_PID" ]; then
    return
  fi

  kill -INT "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
  CAPTURE_PID=""
}

cleanup() {
  stop_capture_process
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
  rm -f "$RESTART_ADMIN_SOCKET"
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
  grep -iE "tun|error|warn|panic|MASQUE|datagram|ICMP" /tmp/ns-srv-restart.log 2>/dev/null | \
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

read_netns_sysctl() {
  local namespace="$1"
  local path="$2"
  ip netns exec "$namespace" cat "$path" 2>/dev/null | tr -d '[:space:]'
}

assert_netns_sysctl() {
  local namespace="$1"
  local path="$2"
  local expected="$3"
  local actual
  actual="$(read_netns_sysctl "$namespace" "$path")"
  if [ "$actual" != "$expected" ]; then
    fail "${namespace} ${path} was not restored: expected ${expected}, observed ${actual:-<missing>}"
  fi
}

assert_no_tun_residue() {
  local namespace
  local details
  for namespace in ns-srv ns-cli; do
    if ! ip netns exec "$namespace" true 2>/dev/null; then
      fail "network namespace ${namespace} disappeared before residue inspection"
    fi
    if details="$(ip netns exec "$namespace" ip -j link show dev qtun0 2>/dev/null)"; then
      fail "managed TUN qtun0 remains in ${namespace} before namespace cleanup: ${details}"
    fi
  done
}

assert_firewall_residue_free() {
  local leftover
  if [ -e "$FIREWALL_OWNER_PATH" ]; then
    fail "durable firewall ownership remains after graceful teardown: $FIREWALL_OWNER_PATH"
  fi
  case "$FIREWALL_BACKEND" in
    nftables)
      leftover="$(ip netns exec ns-srv nft list table inet quicfuscate_rt 2>/dev/null || true)"
      if [ -n "$leftover" ]; then
        fail "nftables routing table remains after graceful teardown: $leftover"
      fi
      ;;
    iptables)
      leftover="$({
        ip netns exec ns-srv iptables-save 2>/dev/null
        ip netns exec ns-srv ip6tables-save 2>/dev/null
      } | grep -E 'QUICFUSCATE_(RT|NAT)' || true)"
      if [ -n "$leftover" ]; then
        fail "iptables routing chains remain after graceful teardown: $leftover"
      fi
      ;;
    *)
      fail "routing state selected an unknown firewall backend: ${FIREWALL_BACKEND:-<missing>}"
      ;;
  esac
}

assert_routing_residue_free() {
  assert_netns_sysctl ns-srv /proc/sys/net/ipv4/ip_forward "$INITIAL_IPV4_FORWARDING"
  assert_netns_sysctl ns-srv /proc/sys/net/ipv6/conf/all/forwarding "$INITIAL_IPV6_FORWARDING"
  assert_no_tun_residue
  assert_firewall_residue_free
}

# --- fail closed before touching certificates or runtime resources ---
if pgrep -x quicfuscate >/dev/null && [ "${QF_E2E_ALLOW_EXISTING_RUNTIME:-0}" != "1" ]; then
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
if [ -e "$RESTART_ADMIN_SOCKET" ]; then
  echo "FAIL: restart admin socket path already exists; refusing to remove unowned path $RESTART_ADMIN_SOCKET" >&2
  exit 2
fi
if [ -e "$ROUTING_STATE_PATH" ]; then
  echo "FAIL: routing ownership state already exists; refusing to remove unowned path $ROUTING_STATE_PATH" >&2
  exit 2
fi
if [ -n "$TRAFFIC_CAPTURE_FILE" ]; then
  if [ -e "$TRAFFIC_CAPTURE_FILE" ] || [ -e "${TRAFFIC_CAPTURE_FILE}.tcpdump.log" ]; then
    echo "FAIL: traffic capture artifact already exists; refusing to overwrite $TRAFFIC_CAPTURE_FILE" >&2
    exit 2
  fi
  if ! [[ "$TRAFFIC_CAPTURE_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "FAIL: QF_E2E_TRAFFIC_CAPTURE_SECONDS must be a positive integer" >&2
    exit 2
  fi
  if ! command -v tcpdump >/dev/null 2>&1; then
    echo "FAIL: tcpdump is required when QF_E2E_TRAFFIC_CAPTURE_FILE is set" >&2
    exit 2
  fi
fi
trap cleanup_on_exit EXIT

# --- ensure server cert valid for the client's hardcoded validation SNI ---
CERT_DIR="$(mktemp -d /tmp/quicfuscate-tun-cert.XXXXXX)"
CERT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"
CA="$CERT_DIR/ca.crt"
if [ -s "$CA_SOURCE" ] && [ -s "$CA_KEY_SOURCE" ]; then
  cp "$CA_SOURCE" "$CA"
  cp "$CA_KEY_SOURCE" "$CERT_DIR/ca.key"
elif [ -n "${QF_E2E_CA:-}" ] || [ -n "${QF_E2E_CA_KEY:-}" ]; then
  fail "explicit CA source is incomplete: $CA_SOURCE / $CA_KEY_SOURCE"
else
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/ca.key" -out "$CA" -days 2 -nodes \
    -subj "/CN=QuicFuscate TUN E2E CA" 2>/dev/null \
    || fail "could not generate isolated test CA"
fi
cd "$CERT_DIR" || fail "could not enter certificate directory"
cat > "$CERT_DIR/leaf-ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:10.10.0.1
EOF
openssl req -newkey rsa:2048 -keyout server.key -out server.csr \
  -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out leaf.crt -days 2 -extfile leaf-ext.cnf 2>/dev/null
cat leaf.crt ca.crt > server.crt
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

INITIAL_IPV4_FORWARDING="$(read_netns_sysctl ns-srv /proc/sys/net/ipv4/ip_forward)"
INITIAL_IPV6_FORWARDING="$(read_netns_sysctl ns-srv /proc/sys/net/ipv6/conf/all/forwarding)"
if ! [[ "$INITIAL_IPV4_FORWARDING" =~ ^[01]$ ]] || ! [[ "$INITIAL_IPV6_FORWARDING" =~ ^[01]$ ]]; then
  fail "could not capture initial server-namespace forwarding state"
fi

echo "=== veth connectivity (cli -> srv) ==="
ip netns exec ns-cli ping -c1 -W2 10.10.0.1 2>&1 | grep -E "bytes from|packet loss"

start_server() {
  local admin_socket="$1"
  local log_path="$2"
  SERVER_LOG_PATH="$log_path"
  ip netns exec ns-srv "$B" server --cert "$CERT" --key "$KEY" \
    --listen 10.10.0.1:4433 --admin-socket "$admin_socket" \
    --qkey-store "$QKEY_STORE" \
    --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
    "${SERVER_PRIVILEGE_ARGS[@]}" "${SERVER_PROFILE_ARGS[@]}" -v "${SERVER_CONFIG_ARGS[@]}" \
    > "$log_path" 2>&1 &
  SERVER_PID=$!
}

wait_for_qkey() {
  local admin_socket="$1"
  local log_path="$2"
  QKEY=""
  for ((attempt = 0; attempt < STARTUP_TIMEOUT; attempt++)); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      break
    fi
    if [ -S "$admin_socket" ]; then
      QKEY=$(echo '{"cmd":"qkey"}' | nc -w 1 -U "$admin_socket" 2>/dev/null | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)
      if [ -n "$QKEY" ]; then
        break
      fi
    fi
    sleep 1
  done
  echo "qkey len: ${#QKEY}"
  if [ -z "$QKEY" ]; then
    cat "$log_path" >&2
    fail "could not issue QKey from admin socket $admin_socket"
  fi
}

# --- start server in ns-srv ---
start_server "$ADMIN_SOCKET" /tmp/ns-srv.log
wait_for_qkey "$ADMIN_SOCKET" /tmp/ns-srv.log

# --- prove process-loss recovery before opening the client data plane ---
if [ ! -f "$ROUTING_STATE_PATH" ]; then
  fail "Linux routing did not publish its durable ownership record: $ROUTING_STATE_PATH"
fi
if ! FIREWALL_BACKEND="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["firewall_backend"])' "$ROUTING_STATE_PATH" 2>/dev/null)"; then
  fail "could not read the selected firewall backend from $ROUTING_STATE_PATH"
fi
if [ "$FIREWALL_BACKEND" != "nftables" ] && [ "$FIREWALL_BACKEND" != "iptables" ]; then
  fail "routing state selected an unsupported firewall backend: ${FIREWALL_BACKEND:-<missing>}"
fi
echo "=== crash/restart routing ownership proof ==="
kill -KILL "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
if [ ! -f "$ROUTING_STATE_PATH" ]; then
  fail "process loss unexpectedly removed the durable routing ownership record"
fi
start_server "$RESTART_ADMIN_SOCKET" /tmp/ns-srv-restart.log
wait_for_qkey "$RESTART_ADMIN_SOCKET" /tmp/ns-srv-restart.log

# --- start client in ns-cli ---
ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
  --qkey "$QKEY" --ca-file "$CA" --verify-peer --disable-doh \
  --tun --tun-name qtun0 --no-utls -v \
  "${CLIENT_CONFIG_ARGS[@]}" \
  > /tmp/ns-cli.log 2>&1 &
CLIENT_PID=$!
sleep 4

# --- require runtime-owned TUN provisioning; never repair missing assignment ---
sleep 2
SERVER_TUN_IPV4="$(ip netns exec ns-srv ip -o -4 addr show dev qtun0 2>/dev/null | awk '{print $4}')"
CLIENT_TUN_IPV4="$(ip netns exec ns-cli ip -o -4 addr show dev qtun0 2>/dev/null | awk '{print $4}')"
if [ "$SERVER_TUN_IPV4" != "10.0.1.1/24" ]; then
  fail "server runtime did not provision exact TUN assignment: ${SERVER_TUN_IPV4:-<missing>}"
fi
if [ "$CLIENT_TUN_IPV4" != "10.0.1.2/24" ]; then
  fail "authenticated server assignment did not provision exact client TUN address: ${CLIENT_TUN_IPV4:-<missing>}"
fi

echo "=== TUN ifaces ==="
echo "srv: $(ip netns exec ns-srv ip -br addr show qtun0 2>&1)"
echo "cli: $(ip netns exec ns-cli ip -br addr show qtun0 2>&1)"
echo "=== handshake status ==="
echo "client_complete=$(grep -c 'TLS handshake complete' /tmp/ns-cli.log) server_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG_PATH")"
if [ "$(grep -c 'TLS handshake complete' /tmp/ns-cli.log)" = "0" ] || [ "$(grep -c 'TLS handshake complete' "$SERVER_LOG_PATH")" = "0" ]; then
  cat "$SERVER_LOG_PATH" >&2
  cat /tmp/ns-cli.log >&2
  fail "TLS handshake did not complete on both sides"
fi

if [ -n "$READY_HOOK" ]; then
  if [ ! -x "$READY_HOOK" ]; then
    fail "QF_E2E_READY_HOOK is not executable: $READY_HOOK"
  fi
  if ! "$READY_HOOK"; then
    fail "QF_E2E_READY_HOOK failed: $READY_HOOK"
  fi
fi

if [ -n "$TRAFFIC_CAPTURE_FILE" ]; then
  mkdir -p "$(dirname "$TRAFFIC_CAPTURE_FILE")"
  CAPTURE_STDERR="${TRAFFIC_CAPTURE_FILE}.tcpdump.log"
  ip netns exec ns-cli tcpdump --immediate-mode -U -n -s 0 -B 4096 -i veth-cli \
    -w "$TRAFFIC_CAPTURE_FILE" \
    'udp and host 10.10.0.2 and host 10.10.0.1 and port 4433' \
    2>"$CAPTURE_STDERR" &
  CAPTURE_PID=$!
  sleep 1
  if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
    cat "$CAPTURE_STDERR" >&2
    fail "tcpdump did not remain active"
  fi
  CLIENT_CPU_TICKS_BEFORE="$(awk '{print $14 + $15}' "/proc/$CLIENT_PID/stat")"
  CLOCK_TICKS_PER_SECOND="$(getconf CLK_TCK)"
  CAPTURE_START_EPOCH="$(python3 -c 'import time; print(f"{time.time():.9f}")')"
  sleep "$TRAFFIC_CAPTURE_SECONDS"
  CAPTURE_END_EPOCH="$(python3 -c 'import time; print(f"{time.time():.9f}")')"
  CLIENT_CPU_TICKS_AFTER="$(awk '{print $14 + $15}' "/proc/$CLIENT_PID/stat")"
  # Keep capture alive past the measured end so libpcap can deliver and flush
  # packets already accepted by the kernel. The analyzer clips the pcap to the
  # exact timestamps above, so this drain interval cannot inflate the result.
  sleep "$TRAFFIC_CAPTURE_DRAIN_SECONDS"
  stop_capture_process
  if [ ! -s "$TRAFFIC_CAPTURE_FILE" ]; then
    fail "traffic capture is empty"
  fi
  CLIENT_CPU_PERCENT="$(
    awk -v before="$CLIENT_CPU_TICKS_BEFORE" \
      -v after="$CLIENT_CPU_TICKS_AFTER" \
      -v ticks="$CLOCK_TICKS_PER_SECOND" \
      -v seconds="$TRAFFIC_CAPTURE_SECONDS" \
      'BEGIN { printf "%.3f", ((after - before) / ticks) * 100 / seconds }'
  )"
  echo "TRAFFIC_CAPTURE file=$TRAFFIC_CAPTURE_FILE duration_seconds=$TRAFFIC_CAPTURE_SECONDS capture_start_epoch=$CAPTURE_START_EPOCH capture_end_epoch=$CAPTURE_END_EPOCH client_cpu_percent=$CLIENT_CPU_PERCENT"
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
echo "srv: $(grep -i 'MASQUE' "$SERVER_LOG_PATH" | tail -3)"
echo "cli: $(grep -i 'MASQUE' /tmp/ns-cli.log | tail -3)"

echo "=== server log tail (TUN/errors) ==="
grep -iE "tun|error|warn|panic|MASQUE" "$SERVER_LOG_PATH" | grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache" | tail -10
echo "=== client log tail (TUN/errors) ==="
grep -iE "tun|error|warn|panic|MASQUE" /tmp/ns-cli.log | grep -vE "rate limiter|Memory|browser|CPU|NEON|SIMD|Cache" | tail -10

# --- graceful shutdown must remove the durable routing record ---
if ! stop_owned_process_gracefully "$CLIENT_PID"; then
  fail "client did not stop gracefully"
fi
CLIENT_PID=""
if ! stop_owned_process_gracefully "$SERVER_PID"; then
  fail "server did not stop gracefully"
fi
SERVER_PID=""
if [ -e "$ROUTING_STATE_PATH" ]; then
  fail "graceful server shutdown left durable routing state behind: $ROUTING_STATE_PATH"
fi

echo "=== routing teardown residue proof ==="
assert_routing_residue_free
echo "forwarding restored: ipv4=${INITIAL_IPV4_FORWARDING} ipv6=${INITIAL_IPV6_FORWARDING}"
echo "TUN links absent: ns-srv/ns-cli qtun0"
echo "firewall residue absent: backend=${FIREWALL_BACKEND}"

# cleanup
cleanup
trap - EXIT
exit 0
