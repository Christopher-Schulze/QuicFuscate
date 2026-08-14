#!/usr/bin/env bash
# Native Linux proof for a one-, two-, or three-hop authenticated MASQUE circuit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
THROUGHPUT_PROBE="$SCRIPT_DIR/utils/tcp-throughput-probe.py"
HOPS="${QF_MULTIHOP_E2E_HOPS:-3}"
STARTUP_TIMEOUT="${QF_E2E_STARTUP_TIMEOUT:-60}"
THROUGHPUT_SECONDS="${QF_MULTIHOP_E2E_THROUGHPUT_SECONDS:-5}"
THROUGHPUT_RATE_BPS="${QF_MULTIHOP_E2E_THROUGHPUT_RATE_BPS:-10000000}"
MIN_THROUGHPUT_RATIO="${QF_MULTIHOP_E2E_MIN_THROUGHPUT_RATIO:-0.70}"
UNDERLAY_MTU="${QF_MULTIHOP_E2E_UNDERLAY_MTU:-1500}"
NETEM_DELAY_MS="${QF_MULTIHOP_E2E_NETEM_DELAY_MS:-0}"
NETEM_JITTER_MS="${QF_MULTIHOP_E2E_NETEM_JITTER_MS:-0}"
NETEM_LOSS_PERCENT="${QF_MULTIHOP_E2E_NETEM_LOSS_PERCENT:-0}"
NETEM_REORDER_PERCENT="${QF_MULTIHOP_E2E_NETEM_REORDER_PERCENT:-0}"
NETEM_DUPLICATE_PERCENT="${QF_MULTIHOP_E2E_NETEM_DUPLICATE_PERCENT:-0}"
MAX_TUNNEL_LOSS_PERCENT="${QF_MULTIHOP_E2E_MAX_TUNNEL_LOSS_PERCENT:-0}"
MAX_RTT_MS="${QF_MULTIHOP_E2E_MAX_RTT_MS:-500}"
MAX_JITTER_MS="${QF_MULTIHOP_E2E_MAX_JITTER_MS:-100}"
MAX_RUNTIME_RSS_KIB="${QF_MULTIHOP_E2E_MAX_RUNTIME_RSS_KIB:-1048576}"
MAX_RUNTIME_CPU_PERCENT="${QF_MULTIHOP_E2E_MAX_RUNTIME_CPU_PERCENT:-400}"
FAILURE_TARGET="${QF_MULTIHOP_E2E_FAILURE_TARGET:-entry}"
WORK_DIR=""
PRESERVE_ARTIFACTS=0
OWNED_NAMESPACES=()
OWNED_PIDS=()
RUNTIME_PIDS=()
CAPTURE_PIDS=()
RUNTIME_NAMESPACES=(qf-mh-cli qf-mh-r1)
STARTED_SERVER_PID=""
R1_SERVER_PID=""
R2_SERVER_PID=""
EXIT_SERVER_PID=""

fail() {
  echo "FAIL: $*" >&2
  for log in "${WORK_DIR:-/nonexistent}"/*.log; do
    [ -f "$log" ] && { echo "=== $log ===" >&2; tail -80 "$log" >&2; }
  done
  exit 1
}

cleanup() {
  local pid namespace
  for pid in "${OWNED_PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "${OWNED_PIDS[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  for namespace in "${OWNED_NAMESPACES[@]}"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
  if [ -n "$WORK_DIR" ] && [ "$PRESERVE_ARTIFACTS" = "0" ]; then
    rm -rf "$WORK_DIR"
  elif [ -n "$WORK_DIR" ]; then
    # Admin Unix-domain sockets are runtime residue, not evidence; remove them
    # so artifact upload does not choke on unsupported entry types.
    find "$WORK_DIR" -type s -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT

remove_owned_pid() {
  local target="$1" pid
  local remaining=()
  for pid in "${OWNED_PIDS[@]}"; do
    [ "$pid" = "$target" ] || remaining+=("$pid")
  done
  OWNED_PIDS=("${remaining[@]}")
}

stop_owned_pid() {
  local pid="$1"
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  remove_owned_pid "$pid"
}

[ "$(id -u)" = "0" ] || fail "root is required"
[ "$HOPS" = "1" ] || [ "$HOPS" = "2" ] || [ "$HOPS" = "3" ] \
  || fail "QF_MULTIHOP_E2E_HOPS must be 1, 2, or 3"
[ "$FAILURE_TARGET" = "entry" ] || [ "$FAILURE_TARGET" = "middle" ] \
  || [ "$FAILURE_TARGET" = "exit" ] \
  || fail "QF_MULTIHOP_E2E_FAILURE_TARGET must be entry, middle, or exit"
[ "$FAILURE_TARGET" != "middle" ] || [ "$HOPS" = "3" ] \
  || fail "middle failure proof requires a three-hop circuit"
[ -x "$BINARY" ] || fail "release binary is missing: $BINARY"
for command in getconf ip openssl nc python3 tcpdump timeout; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[ "$NETEM_DELAY_MS" = "0" ] && [ "$NETEM_JITTER_MS" = "0" ] \
  && [ "$NETEM_LOSS_PERCENT" = "0" ] && [ "$NETEM_REORDER_PERCENT" = "0" ] \
  && [ "$NETEM_DUPLICATE_PERCENT" = "0" ] || command -v tc >/dev/null 2>&1 \
  || fail "tc is required for the configured impairment profile"
[ -r "$THROUGHPUT_PROBE" ] || fail "throughput probe is unreadable: $THROUGHPUT_PROBE"
[[ "$THROUGHPUT_SECONDS" =~ ^[0-9]+$ ]] && [ "$THROUGHPUT_SECONDS" -ge 5 ] \
  || fail "QF_MULTIHOP_E2E_THROUGHPUT_SECONDS must be an integer of at least 5"
[[ "$THROUGHPUT_RATE_BPS" =~ ^[0-9]+$ ]] && [ "$THROUGHPUT_RATE_BPS" -ge 1000000 ] \
  || fail "QF_MULTIHOP_E2E_THROUGHPUT_RATE_BPS must be an integer of at least 1000000"
python3 - "$MIN_THROUGHPUT_RATIO" <<'PY' || fail "QF_MULTIHOP_E2E_MIN_THROUGHPUT_RATIO must be in (0, 1]"
import sys
value = float(sys.argv[1])
assert 0 < value <= 1
PY
python3 - "$UNDERLAY_MTU" "$NETEM_DELAY_MS" "$NETEM_JITTER_MS" \
  "$NETEM_LOSS_PERCENT" "$NETEM_REORDER_PERCENT" "$NETEM_DUPLICATE_PERCENT" \
  "$MAX_TUNNEL_LOSS_PERCENT" "$MAX_RTT_MS" "$MAX_JITTER_MS" \
  "$MAX_RUNTIME_RSS_KIB" "$MAX_RUNTIME_CPU_PERCENT" <<'PY' \
  || fail "invalid multi-hop network or performance threshold"
import sys

underlay_mtu = int(sys.argv[1])
delay_ms = float(sys.argv[2])
jitter_ms = float(sys.argv[3])
loss_percent = float(sys.argv[4])
reorder_percent = float(sys.argv[5])
duplicate_percent = float(sys.argv[6])
max_loss_percent = float(sys.argv[7])
max_rtt_ms = float(sys.argv[8])
max_jitter_ms = float(sys.argv[9])
max_rss_kib = int(sys.argv[10])
max_cpu_percent = float(sys.argv[11])

assert 1280 <= underlay_mtu <= 9000
assert delay_ms >= 0 and jitter_ms >= 0
assert 0 <= loss_percent <= 20
assert 0 <= reorder_percent <= 20
assert 0 <= duplicate_percent <= 20
assert 0 <= max_loss_percent <= 100
assert max_rtt_ms > 0 and max_jitter_ms >= 0
assert max_rss_kib > 0 and max_cpu_percent > 0
assert reorder_percent == 0 or delay_ms > 0
PY

for namespace in qf-mh-cli qf-mh-r1 qf-mh-r2 qf-mh-exit; do
  if ip netns list | grep -Eq "^${namespace}([[:space:]]|$)"; then
    fail "refusing to remove pre-existing namespace $namespace"
  fi
done

if [ -n "${QF_MULTIHOP_E2E_ARTIFACT_DIR:-}" ]; then
  case "$QF_MULTIHOP_E2E_ARTIFACT_DIR" in
    /*) ;;
    *) fail "QF_MULTIHOP_E2E_ARTIFACT_DIR must be an absolute path" ;;
  esac
  [ ! -e "$QF_MULTIHOP_E2E_ARTIFACT_DIR" ] \
    || fail "refusing to replace existing artifact path: $QF_MULTIHOP_E2E_ARTIFACT_DIR"
  mkdir -m 700 "$QF_MULTIHOP_E2E_ARTIFACT_DIR"
  WORK_DIR="$QF_MULTIHOP_E2E_ARTIFACT_DIR"
  PRESERVE_ARTIFACTS=1
else
  WORK_DIR="$(mktemp -d /tmp/quicfuscate-multihop.XXXXXX)"
fi

create_namespace() {
  ip netns add "$1"
  OWNED_NAMESPACES+=("$1")
  ip netns exec "$1" ip link set lo up
}

create_link() {
  local left_ns="$1" left_if="$2" left_addr="$3"
  local right_ns="$4" right_if="$5" right_addr="$6"
  ip link add "$left_if" type veth peer name "$right_if"
  ip link set "$left_if" netns "$left_ns"
  ip link set "$right_if" netns "$right_ns"
  ip netns exec "$left_ns" ip addr add "$left_addr" dev "$left_if"
  ip netns exec "$right_ns" ip addr add "$right_addr" dev "$right_if"
  ip netns exec "$left_ns" ip link set "$left_if" mtu "$UNDERLAY_MTU"
  ip netns exec "$right_ns" ip link set "$right_if" mtu "$UNDERLAY_MTU"
  ip netns exec "$left_ns" ip link set "$left_if" up
  ip netns exec "$right_ns" ip link set "$right_if" up
}

create_namespace qf-mh-cli
create_namespace qf-mh-r1
create_link qf-mh-cli mh-cli 10.41.0.2/24 qf-mh-r1 mh-r1-in 10.41.0.1/24
if [ "$NETEM_DELAY_MS" != "0" ] || [ "$NETEM_JITTER_MS" != "0" ] \
  || [ "$NETEM_LOSS_PERCENT" != "0" ] || [ "$NETEM_REORDER_PERCENT" != "0" ] \
  || [ "$NETEM_DUPLICATE_PERCENT" != "0" ]; then
  ip netns exec qf-mh-cli tc qdisc add dev mh-cli root netem \
    delay "${NETEM_DELAY_MS}ms" "${NETEM_JITTER_MS}ms" \
    loss "${NETEM_LOSS_PERCENT}%" reorder "${NETEM_REORDER_PERCENT}%" \
    duplicate "${NETEM_DUPLICATE_PERCENT}%" \
    || fail "could not apply the configured entry-link impairment profile"
fi
if [ "$HOPS" -ge 2 ]; then
  create_namespace qf-mh-r2
  RUNTIME_NAMESPACES+=(qf-mh-r2)
  create_link qf-mh-r1 mh-r1-out 10.42.0.1/24 qf-mh-r2 mh-r2-in 10.42.0.2/24
fi
if [ "$HOPS" = "3" ]; then
  create_namespace qf-mh-exit
  RUNTIME_NAMESPACES+=(qf-mh-exit)
  create_link qf-mh-r2 mh-r2-out 10.43.0.1/24 qf-mh-exit mh-exit 10.43.0.2/24
fi

EXIT_NS=qf-mh-r1
[ "$HOPS" = "2" ] && EXIT_NS=qf-mh-r2
[ "$HOPS" = "3" ] && EXIT_NS=qf-mh-exit

configure_exit_default_route() {
  local gateway interface
  case "$HOPS" in
    1) gateway=10.41.0.2; interface=mh-r1-in ;;
    2) gateway=10.42.0.1; interface=mh-r2-in ;;
    3) gateway=10.43.0.1; interface=mh-exit ;;
  esac
  ip netns exec "$EXIT_NS" ip route replace default via "$gateway" dev "$interface" \
    || fail "could not configure the exit default route via $gateway on $interface"
}

configure_exit_default_route
INITIAL_IPV4_FORWARDING="$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/ip_forward)"
INITIAL_IPV6_FORWARDING="$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv6/conf/all/forwarding)"

CA="$WORK_DIR/ca.crt"
CA_KEY="$WORK_DIR/ca.key"
CERT="$WORK_DIR/server.crt"
KEY="$WORK_DIR/server.key"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=QuicFuscate Multi-Hop CA" \
  -keyout "$CA_KEY" -out "$CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=circuit.test" \
  -keyout "$KEY" -out "$WORK_DIR/server.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:circuit.test' > "$WORK_DIR/leaf-ext.cnf"
openssl x509 -req -days 2 -in "$WORK_DIR/server.csr" -CA "$CA" -CAkey "$CA_KEY" \
  -CAcreateserial -extfile "$WORK_DIR/leaf-ext.cnf" -out "$WORK_DIR/leaf.crt" >/dev/null 2>&1
cp "$WORK_DIR/leaf.crt" "$CERT"
printf '\n' >> "$CERT"
sed -n '1,$p' "$CA" >> "$CERT"

start_server() {
  local namespace="$1" listen="$2" socket="$3" store="$4" log="$5" mode="$6" next="$7"
  local args=(server --listen "$listen" --cert "$CERT" --key "$KEY" --admin-socket "$socket"
    --qkey-store "$store" --no-drop-privileges -v)
  if [ "$mode" = "exit" ]; then
    args+=(--tun --tun-name qtun0 --tun-ip 10.51.0.1 --tun-netmask 255.255.255.0
      --tun-ip6 fd51::1 --tun-prefix6 64 --vpn-dns 10.51.0.1)
    ip netns exec "$namespace" env QUICFUSCATE_MASQUE_TRACE=1 \
      "$BINARY" "${args[@]}" > "$log" 2>&1 &
  else
    ip netns exec "$namespace" env \
      QUICFUSCATE_MASQUE_TRACE=1 \
      QUICFUSCATE_MASQUE_RELAY_ENABLED=1 \
      QUICFUSCATE_MASQUE_RELAY_ALLOW_NON_GLOBAL_TARGETS=1 \
      QUICFUSCATE_MASQUE_RELAY_ALLOWED_HOSTS="$next" \
      QUICFUSCATE_MASQUE_RELAY_ALLOWED_CIDRS="${next%.*}.0/24" \
      QUICFUSCATE_MASQUE_RELAY_ALLOWED_PORTS=4433 \
      "$BINARY" "${args[@]}" > "$log" 2>&1 &
  fi
  STARTED_SERVER_PID="$!"
  OWNED_PIDS+=("$STARTED_SERVER_PID")
  RUNTIME_PIDS+=("$STARTED_SERVER_PID")
}

wait_for_qkey() {
  local socket="$1" qkey=""
  for ((attempt = 0; attempt < STARTUP_TIMEOUT; attempt++)); do
    if [ -S "$socket" ]; then
      qkey="$(printf '%s\n' '{"cmd":"qkey"}' | nc -w 1 -U "$socket" 2>/dev/null | \
        python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["qkey"])' 2>/dev/null || true)"
      [ -n "$qkey" ] && { printf '%s' "$qkey"; return 0; }
    fi
    sleep 1
  done
  return 1
}

if [ "$HOPS" = "3" ]; then
  start_server qf-mh-exit 10.43.0.2:4433 "$WORK_DIR/exit.sock" "$WORK_DIR/exit-qkeys.json" "$WORK_DIR/exit.log" exit ""
  EXIT_SERVER_PID="$STARTED_SERVER_PID"
  start_server qf-mh-r2 10.42.0.2:4433 "$WORK_DIR/r2.sock" "$WORK_DIR/r2-qkeys.json" "$WORK_DIR/r2.log" relay 10.43.0.2
  R2_SERVER_PID="$STARTED_SERVER_PID"
elif [ "$HOPS" = "2" ]; then
  start_server qf-mh-r2 10.42.0.2:4433 "$WORK_DIR/exit.sock" "$WORK_DIR/exit-qkeys.json" "$WORK_DIR/exit.log" exit ""
  EXIT_SERVER_PID="$STARTED_SERVER_PID"
fi
if [ "$HOPS" = "1" ]; then
  start_server qf-mh-r1 10.41.0.1:4433 "$WORK_DIR/exit.sock" "$WORK_DIR/exit-qkeys.json" "$WORK_DIR/exit.log" exit ""
  R1_SERVER_PID="$STARTED_SERVER_PID"
  EXIT_SERVER_PID="$STARTED_SERVER_PID"
else
  start_server qf-mh-r1 10.41.0.1:4433 "$WORK_DIR/r1.sock" "$WORK_DIR/r1-qkeys.json" "$WORK_DIR/r1.log" relay 10.42.0.2
  R1_SERVER_PID="$STARTED_SERVER_PID"
fi

if [ "$HOPS" -ge 2 ]; then
  QKEY_R1="$(wait_for_qkey "$WORK_DIR/r1.sock")" || fail "entry QKey issuance failed"
fi
if [ "$HOPS" = "3" ]; then
  QKEY_R2="$(wait_for_qkey "$WORK_DIR/r2.sock")" || fail "relay QKey issuance failed"
fi
QKEY_EXIT="$(wait_for_qkey "$WORK_DIR/exit.sock")" || fail "exit QKey issuance failed"

qkey_field() {
  QKEY_VALUE="$1" QKEY_FIELD="$2" python3 - <<'PY'
import base64, hashlib, json, os
qkey = os.environ["QKEY_VALUE"].strip()
if os.environ["QKEY_FIELD"] == "id":
    print(hashlib.sha256(("QKey-" + qkey[5:]).encode()).hexdigest()[:12])
else:
    payload = qkey[5:] + "=" * ((4 - len(qkey[5:]) % 4) % 4)
    print(json.loads(base64.urlsafe_b64decode(payload))["token"])
PY
}

EXIT_ID="$(qkey_field "$QKEY_EXIT" id)"; EXIT_TOKEN="$(qkey_field "$QKEY_EXIT" token)"
if [ "$HOPS" -ge 2 ]; then
  R1_ID="$(qkey_field "$QKEY_R1" id)"; R1_TOKEN="$(qkey_field "$QKEY_R1" token)"
fi
if [ "$HOPS" = "3" ]; then
  R2_ID="$(qkey_field "$QKEY_R2" id)"; R2_TOKEN="$(qkey_field "$QKEY_R2" token)"
fi

CONFIG="$WORK_DIR/client.toml"
{
  printf '%s\n' '[engine]' 'mode = "client"' '[interface]' 'type = "tun"' 'tun_name = "qtun0"' 'dns_servers = ["10.51.0.1"]'
  printf '%s\n' '[stealth]' 'enable_doh = false'
  printf '%s\n' '[security]' 'kill_switch = true' '[circuit]' "max_hops = $HOPS" 'max_parallel_circuits = 2' 'allow_single_hop_fallback = false'
  if [ "$HOPS" -ge 2 ]; then
    printf '%s\n' '[[circuit.hops]]' 'label = "Entry"' 'endpoint = "10.41.0.1:4433"' 'sni = "circuit.test"' 'verify_peer = true' "ca_file = \"$CA\"" "qkey_id = \"$R1_ID\"" 'qkey_token_ref = "env:QF_MH_R1_TOKEN"' 'role = "relay"' 'connect_timeout_ms = 30000'
  fi
  if [ "$HOPS" = "3" ]; then
    printf '%s\n' '[[circuit.hops]]' 'label = "Relay"' 'endpoint = "10.42.0.2:4433"' 'sni = "circuit.test"' 'verify_peer = true' "ca_file = \"$CA\"" "qkey_id = \"$R2_ID\"" 'qkey_token_ref = "env:QF_MH_R2_TOKEN"' 'role = "relay"' 'connect_timeout_ms = 30000'
    exit_endpoint=10.43.0.2:4433
  else
    if [ "$HOPS" = "2" ]; then
      exit_endpoint=10.42.0.2:4433
    else
      exit_endpoint=10.41.0.1:4433
    fi
  fi
  printf '%s\n' '[[circuit.hops]]' 'label = "Exit"' "endpoint = \"$exit_endpoint\"" 'sni = "circuit.test"' 'verify_peer = true' "ca_file = \"$CA\"" "qkey_id = \"$EXIT_ID\"" 'qkey_token_ref = "env:QF_MH_EXIT_TOKEN"' 'role = "exit"' 'connect_timeout_ms = 30000'
} > "$CONFIG"

ip netns exec qf-mh-cli env QUICFUSCATE_MASQUE_TRACE=1 \
  QF_MH_R1_TOKEN="${R1_TOKEN:-$EXIT_TOKEN}" QF_MH_R2_TOKEN="${R2_TOKEN:-$EXIT_TOKEN}" \
  QF_MH_EXIT_TOKEN="$EXIT_TOKEN" "$BINARY" client --remote 10.41.0.1:4433 --config "$CONFIG" \
  > "$WORK_DIR/client.log" 2>&1 &
CLIENT_PID=$!
OWNED_PIDS+=("$CLIENT_PID")
RUNTIME_PIDS+=("$CLIENT_PID")

for ((attempt = 0; attempt < STARTUP_TIMEOUT; attempt++)); do
  CLIENT_TUN="$(ip netns exec qf-mh-cli ip -o -4 addr show dev qtun0 2>/dev/null | awk '{print $4}' || true)"
  [ "$CLIENT_TUN" = "10.51.0.2/24" ] && break
  kill -0 "$CLIENT_PID" 2>/dev/null || fail "circuit client exited during startup"
  sleep 1
done
[ "${CLIENT_TUN:-}" = "10.51.0.2/24" ] || fail "client TUN assignment did not become ready"

CLIENT_TUN_IPV6="$(ip netns exec qf-mh-cli ip -o -6 addr show dev qtun0 scope global | awk '{print $4}')"
[ "$CLIENT_TUN_IPV6" = "fd51::2/64" ] || fail "client IPv6 TUN assignment is missing"

start_capture() {
  local namespace="$1" interface="$2" output="$3"
  ip netns exec "$namespace" tcpdump --immediate-mode -l -nn -i "$interface" udp \
    > "$output" 2> "${output}.stderr" &
  local pid=$!
  OWNED_PIDS+=("$pid")
  CAPTURE_PIDS+=("$pid")
}

finish_captures() {
  local pid
  for pid in "${CAPTURE_PIDS[@]}"; do
    stop_owned_pid "$pid"
  done
  CAPTURE_PIDS=()
}

assert_capture_seen() {
  local capture="$1" pattern="$2"
  grep -Eq "$pattern" "$capture" || fail "adjacency capture missing expected traffic: $capture / $pattern"
}

assert_capture_absent() {
  local capture="$1" pattern="$2"
  if grep -Eq "$pattern" "$capture"; then
    fail "adjacency capture exposed a non-adjacent endpoint: $capture / $pattern"
  fi
}

start_capture qf-mh-cli mh-cli "$WORK_DIR/client-underlay.log"
start_capture qf-mh-r1 any "$WORK_DIR/r1-underlay.log"
if [ "$HOPS" -ge 2 ]; then
  start_capture qf-mh-r2 any "$WORK_DIR/r2-underlay.log"
fi
if [ "$HOPS" = "3" ]; then
  start_capture qf-mh-exit mh-exit "$WORK_DIR/exit-underlay.log"
fi
sleep 1

ip netns exec "$EXIT_NS" python3 -c '
import select, socket
tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); tcp.bind(("10.51.0.1", 18080)); tcp.listen()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("10.51.0.1", 18080))
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(("10.51.0.1", 53))
while True:
    for current in select.select([tcp, udp, dns], [], [])[0]:
        if current is tcp:
            connection, _ = tcp.accept(); payload = connection.recv(65535); connection.sendall(payload); connection.close()
        else:
            payload, peer = current.recvfrom(65535)
            if current is dns:
                payload = payload[:2] + b"\x81\x83" + payload[4:6] + b"\x00\x00\x00\x00\x00\x00" + payload[12:]
            current.sendto(payload, peer)
' > "$WORK_DIR/exit-services.log" 2>&1 &
SERVICE_PID=$!
OWNED_PIDS+=("$SERVICE_PID")
sleep 1

assert_ping_thresholds() {
  local label="$1" output="$2"
  python3 - "$label" "$MAX_TUNNEL_LOSS_PERCENT" "$MAX_RTT_MS" "$MAX_JITTER_MS" \
    "$WORK_DIR/ping-metrics.tsv" "$output" <<'PY' \
    || fail "$label exceeded a circuit latency, jitter, or loss threshold"
import re
import sys

label, max_loss, max_rtt, max_jitter, metrics_path, output = sys.argv[1:]
loss = re.search(r"([0-9.]+)% packet loss", output)
rtt = re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms", output)
assert loss is not None, output
loss_percent = float(loss.group(1))
assert loss_percent <= float(max_loss), (label, loss_percent, max_loss)
maximum_ms = 0.0
jitter_ms = 0.0
if rtt is not None:
    maximum_ms = float(rtt.group(3))
    jitter_ms = float(rtt.group(4))
    assert maximum_ms <= float(max_rtt), (label, maximum_ms, max_rtt)
    assert jitter_ms <= float(max_jitter), (label, jitter_ms, max_jitter)
    print(f"{label}_loss_percent={loss_percent:.3f} {label}_max_rtt_ms={maximum_ms:.3f} {label}_jitter_ms={jitter_ms:.3f}")
else:
    print(f"{label}_loss_percent={loss_percent:.3f}")
with open(metrics_path, "a", encoding="utf-8") as handle:
    handle.write(f"{label}\t{loss_percent}\t{maximum_ms}\t{jitter_ms}\n")
PY
}

PING="$(ip netns exec qf-mh-cli ping -c 10 -W 3 -I qtun0 10.51.0.1 2>&1)"
echo "$PING"
assert_ping_thresholds client_ipv4 "$PING"
EXIT_PING="$(ip netns exec "$EXIT_NS" ping -c 10 -W 3 -I qtun0 10.51.0.2 2>&1)"
assert_ping_thresholds exit_ipv4 "$EXIT_PING"
IPV6_PING="$(ip netns exec qf-mh-cli ping -6 -c 10 -W 3 -I qtun0 fd51::1 2>&1)"
assert_ping_thresholds client_ipv6 "$IPV6_PING"
TCP_REPLY="$(printf 'tcp-through-circuit' | ip netns exec qf-mh-cli nc -w 3 10.51.0.1 18080)"
[ "$TCP_REPLY" = "tcp-through-circuit" ] || fail "$HOPS-hop TCP echo failed"
UDP_REPLY="$(printf 'udp-through-circuit' | ip netns exec qf-mh-cli nc -u -w 3 10.51.0.1 18080)"
[ "$UDP_REPLY" = "udp-through-circuit" ] || fail "$HOPS-hop UDP echo failed"
ip netns exec qf-mh-cli python3 -c '
import socket
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x00\x00\x01\x00\x01"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(3); sock.sendto(query, ("10.51.0.1", 53)); response, _ = sock.recvfrom(512)
assert response[:2] == b"\x12\x34" and response[2] & 0x80
' || fail "$HOPS-hop DNS datagram failed"

THROUGHPUT_TIMEOUT=$((THROUGHPUT_SECONDS + 15))
CLK_TCK="$(getconf CLK_TCK)"
runtime_cpu_ticks() {
  local pid total=0 ticks
  for pid in "${RUNTIME_PIDS[@]}"; do
    [ -r "/proc/$pid/stat" ] || continue
    ticks="$(awk '{print $14 + $15}' "/proc/$pid/stat")"
    total=$((total + ticks))
  done
  printf '%s\n' "$total"
}
runtime_rss_kib() {
  local pid total=0 rss
  for pid in "${RUNTIME_PIDS[@]}"; do
    [ -r "/proc/$pid/status" ] || continue
    rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
    total=$((total + ${rss:-0}))
  done
  printf '%s\n' "$total"
}
CPU_TICKS_BEFORE="$(runtime_cpu_ticks)"
RSS_KIB_BEFORE="$(runtime_rss_kib)"
ip netns exec "$EXIT_NS" timeout "$THROUGHPUT_TIMEOUT" \
  python3 "$THROUGHPUT_PROBE" server \
  --bind fd51::1 --port 18081 --timeout "$((THROUGHPUT_SECONDS + 10))" \
  --result "$WORK_DIR/throughput-server-${HOPS}hop.json" \
  > "$WORK_DIR/throughput-server-${HOPS}hop.log" 2>&1 &
THROUGHPUT_SERVER_PID=$!
OWNED_PIDS+=("$THROUGHPUT_SERVER_PID")
RESOURCE_SAMPLES="$WORK_DIR/runtime-rss-kib.samples"
(
  while kill -0 "$THROUGHPUT_SERVER_PID" 2>/dev/null; do
    runtime_rss_kib
    sleep 0.1
  done
) > "$RESOURCE_SAMPLES" &
RESOURCE_SAMPLER_PID=$!
OWNED_PIDS+=("$RESOURCE_SAMPLER_PID")
ip netns exec qf-mh-cli timeout "$THROUGHPUT_TIMEOUT" \
  python3 "$THROUGHPUT_PROBE" client \
  --source fd51::2 --destination fd51::1 --port 18081 \
  --duration "$THROUGHPUT_SECONDS" --rate-bps "$THROUGHPUT_RATE_BPS" \
  --timeout "$((THROUGHPUT_SECONDS + 10))" \
  --result "$WORK_DIR/throughput-client-${HOPS}hop.json" \
  || fail "$HOPS-hop receiver-verified TCP throughput probe failed"
wait "$THROUGHPUT_SERVER_PID" || fail "$HOPS-hop throughput receiver failed"
remove_owned_pid "$THROUGHPUT_SERVER_PID"
wait "$RESOURCE_SAMPLER_PID"
remove_owned_pid "$RESOURCE_SAMPLER_PID"
CPU_TICKS_AFTER="$(runtime_cpu_ticks)"
RSS_KIB_AFTER="$(runtime_rss_kib)"
RUNTIME_RSS_KIB="$RSS_KIB_BEFORE"
[ "$RSS_KIB_AFTER" -le "$RUNTIME_RSS_KIB" ] || RUNTIME_RSS_KIB="$RSS_KIB_AFTER"
SAMPLED_RSS_KIB="$(sort -n "$RESOURCE_SAMPLES" | tail -1)"
[ "${SAMPLED_RSS_KIB:-0}" -le "$RUNTIME_RSS_KIB" ] || RUNTIME_RSS_KIB="$SAMPLED_RSS_KIB"
python3 - "$WORK_DIR/throughput-client-${HOPS}hop.json" \
  "$WORK_DIR/performance-${HOPS}hop.json" "$WORK_DIR/ping-metrics.tsv" \
  "$HOPS" "$THROUGHPUT_RATE_BPS" \
  "$MIN_THROUGHPUT_RATIO" "$CPU_TICKS_BEFORE" "$CPU_TICKS_AFTER" "$CLK_TCK" \
  "$THROUGHPUT_SECONDS" "$RUNTIME_RSS_KIB" "$MAX_RUNTIME_RSS_KIB" \
  "$MAX_RUNTIME_CPU_PERCENT" "$UNDERLAY_MTU" "$NETEM_DELAY_MS" \
  "$NETEM_JITTER_MS" "$NETEM_LOSS_PERCENT" "$NETEM_REORDER_PERCENT" \
  "$NETEM_DUPLICATE_PERCENT" <<'PY' \
  || fail "$HOPS-hop performance fell outside a release threshold"
import json
import sys

result = json.load(open(sys.argv[1], encoding="utf-8"))
artifact_path = sys.argv[2]
ping_metrics_path = sys.argv[3]
hops = int(sys.argv[4])
configured = float(sys.argv[5])
minimum_ratio = float(sys.argv[6])
cpu_ticks = max(0, int(sys.argv[8]) - int(sys.argv[7]))
clock_ticks = int(sys.argv[9])
duration_seconds = float(sys.argv[10])
runtime_rss_kib = int(sys.argv[11])
max_runtime_rss_kib = int(sys.argv[12])
max_runtime_cpu_percent = float(sys.argv[13])
observed = float(result["receiver_bits_per_second"])
runtime_cpu_percent = 100.0 * cpu_ticks / (clock_ticks * duration_seconds)
assert observed >= configured * minimum_ratio, (observed, configured, minimum_ratio)
assert result["bytes_sent"] == result["receiver"]["bytes"]
assert result["sha256"] == result["receiver"]["sha256"]
assert runtime_rss_kib <= max_runtime_rss_kib, (runtime_rss_kib, max_runtime_rss_kib)
assert runtime_cpu_percent <= max_runtime_cpu_percent, (
    runtime_cpu_percent,
    max_runtime_cpu_percent,
)
ping_metrics = {}
with open(ping_metrics_path, encoding="utf-8") as handle:
    for line in handle:
        label, loss, maximum_rtt, jitter = line.rstrip("\n").split("\t")
        ping_metrics[label] = {
            "loss_percent": float(loss),
            "maximum_rtt_ms": float(maximum_rtt),
            "jitter_ms": float(jitter),
        }
artifact = {
    "status": "PASS",
    "hops": hops,
    "throughput": {
        "configured_bits_per_second": configured,
        "receiver_bits_per_second": observed,
        "retained_ratio": observed / configured,
        "minimum_retained_ratio": minimum_ratio,
        "bytes": result["bytes_sent"],
        "sha256": result["sha256"],
    },
    "runtime": {
        "aggregate_cpu_percent": runtime_cpu_percent,
        "maximum_cpu_percent": max_runtime_cpu_percent,
        "aggregate_rss_kib": runtime_rss_kib,
        "maximum_rss_kib": max_runtime_rss_kib,
    },
    "tunnel_ping": ping_metrics,
    "underlay": {
        "mtu": int(sys.argv[14]),
        "delay_ms": float(sys.argv[15]),
        "jitter_ms": float(sys.argv[16]),
        "loss_percent": float(sys.argv[17]),
        "reorder_percent": float(sys.argv[18]),
        "duplicate_percent": float(sys.argv[19]),
    },
}
with open(artifact_path, "x", encoding="utf-8") as handle:
    json.dump(artifact, handle, sort_keys=True, indent=2)
    handle.write("\n")
print(
    f"throughput_receiver_bps={observed:.0f} retained_ratio={observed / configured:.4f} "
    f"runtime_cpu_percent={runtime_cpu_percent:.3f} runtime_rss_kib={runtime_rss_kib}"
)
PY
grep -q 'Circuit client connected from canonical engine configuration' "$WORK_DIR/client.log" \
  || fail "CLI did not use the canonical circuit engine path"

finish_captures
assert_capture_seen "$WORK_DIR/client-underlay.log" '10\.41\.0\.2\.[0-9]+ > 10\.41\.0\.1\.4433'
assert_capture_absent "$WORK_DIR/client-underlay.log" '10\.(42|43)\.0\.2\.4433'
assert_capture_seen "$WORK_DIR/r1-underlay.log" '10\.41\.0\.(1\.4433|2\.[0-9]+)'
if [ "$HOPS" = "3" ]; then
  assert_capture_seen "$WORK_DIR/r1-underlay.log" '10\.42\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_absent "$WORK_DIR/r1-underlay.log" '10\.43\.0\.2\.4433'
  assert_capture_seen "$WORK_DIR/r2-underlay.log" '10\.42\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_seen "$WORK_DIR/r2-underlay.log" '10\.43\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_absent "$WORK_DIR/r2-underlay.log" '10\.41\.0\.2\.[0-9]+'
  assert_capture_seen "$WORK_DIR/exit-underlay.log" '10\.43\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_absent "$WORK_DIR/exit-underlay.log" '10\.(41|42)\.0\.2\.[0-9]+'
elif [ "$HOPS" = "2" ]; then
  assert_capture_seen "$WORK_DIR/r1-underlay.log" '10\.42\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_seen "$WORK_DIR/r2-underlay.log" '10\.42\.0\.(1\.[0-9]+|2\.4433)'
  assert_capture_absent "$WORK_DIR/r2-underlay.log" '10\.41\.0\.2\.[0-9]+'
else
  assert_capture_absent "$WORK_DIR/r1-underlay.log" '10\.(42|43)\.0\.2\.4433'
fi

if [ "$HOPS" -ge 2 ]; then
  FAILURE_PID="$R1_SERVER_PID"
  [ "$FAILURE_TARGET" != "middle" ] || FAILURE_PID="$R2_SERVER_PID"
  [ "$FAILURE_TARGET" != "exit" ] || FAILURE_PID="$EXIT_SERVER_PID"
  [ -n "$FAILURE_PID" ] || fail "selected circuit failure target has no runtime owner"
  kill -KILL "$FAILURE_PID"
  wait "$FAILURE_PID" 2>/dev/null || true
  remove_owned_pid "$FAILURE_PID"
  if ip netns exec qf-mh-cli ping -c 3 -W 1 -I qtun0 10.51.0.1 \
    > "$WORK_DIR/${FAILURE_TARGET}-crash-ping.log" 2>&1; then
    fail "tunnel traffic survived loss of the required $FAILURE_TARGET circuit owner"
  fi
  if ip netns exec qf-mh-cli ping -c 1 -W 1 10.42.0.2 \
    > "$WORK_DIR/direct-fallback-ping.log" 2>&1; then
    fail "client reached a non-entry relay directly after circuit failure"
  fi
fi

stop_owned_pid "$CLIENT_PID"
if ip netns exec qf-mh-cli ip link show qtun0 >/dev/null 2>&1; then
  fail "client TUN residue remains after graceful shutdown"
fi

for pid in "${OWNED_PIDS[@]}"; do
  kill -TERM "$pid" 2>/dev/null || true
done
for pid in "${OWNED_PIDS[@]}"; do
  wait "$pid" 2>/dev/null || true
done
OWNED_PIDS=()

for namespace in "${RUNTIME_NAMESPACES[@]}"; do
  if ip netns exec "$namespace" ip link show qtun0 >/dev/null 2>&1; then
    fail "TUN residue remains in $namespace after graceful shutdown"
  fi
  if command -v iptables-save >/dev/null 2>&1 \
    && ip netns exec "$namespace" iptables-save 2>/dev/null | grep -q 'QUICFUSCATE'; then
    fail "iptables residue remains in $namespace after graceful shutdown"
  fi
  if command -v nft >/dev/null 2>&1 \
    && ip netns exec "$namespace" nft list tables 2>/dev/null | grep -qi 'quicfuscate'; then
    fail "nftables residue remains in $namespace after graceful shutdown"
  fi
done
[ "$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv4/ip_forward)" = "$INITIAL_IPV4_FORWARDING" ] \
  || fail "IPv4 forwarding was not restored after graceful shutdown"
[ "$(ip netns exec "$EXIT_NS" cat /proc/sys/net/ipv6/conf/all/forwarding)" = "$INITIAL_IPV6_FORWARDING" ] \
  || fail "IPv6 forwarding was not restored after graceful shutdown"

echo "PASS: authenticated ${HOPS}-hop MASQUE circuit carried bidirectional IPv4/IPv6 ICMP, TCP, UDP, and DNS within measured throughput/CPU/RSS/latency/jitter/loss bounds, failed closed on ${FAILURE_TARGET} loss, exposed adjacent-only underlay traffic, and left zero owned runtime residue"
[ "$PRESERVE_ARTIFACTS" = "0" ] || echo "Artifacts: $WORK_DIR"
