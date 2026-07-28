#!/usr/bin/env bash
# Three-client dual-stack TUN proof for TODO-523.
#
# Proves authenticated source ownership, default-deny client unicast, explicit
# client-unicast opt-in, IPv4 broadcast/multicast and IPv6 multicast fan-out,
# typed routing metrics, ICMP PTB/TTL behavior, IPv6 forwarding/NAT state,
# DPLPMTUD black-hole recovery/re-probe, and sustained IPv6 throughput through
# the production H3/MASQUE data plane.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CERT="${QF_E2E_CERT:-}"
KEY="${QF_E2E_KEY:-}"
CA="${QF_E2E_CA:-$PROJECT_ROOT/config/local/ca.crt}"
CA_KEY="${QF_E2E_CA_KEY:-$PROJECT_ROOT/config/local/ca.key}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-todo523-$$}"
THROUGHPUT_PROBE="$SCRIPT_DIR/utils/tcp-throughput-probe.py"
EGRESS_SUMMARIZER="$SCRIPT_DIR/utils/summarize-external-egress.py"
UDP_SOCKET_EVIDENCE="$SCRIPT_DIR/utils/udp-socket-evidence.py"
THROUGHPUT_TRIAL_SECONDS="${QF_E2E_THROUGHPUT_TRIAL_SECONDS:-10}"
THROUGHPUT_RATE_BPS="${QF_E2E_THROUGHPUT_RATE_BPS:-15000000}"
EXTERNAL_EGRESS_CAPTURE="${QF_E2E_EXTERNAL_EGRESS_CAPTURE:-0}"

SERVER_NS="qf523s"
CLIENT_NS=("qf523c1" "qf523c2" "qf523c3")
CLIENT_V4=("10.0.1.2" "10.0.1.3" "10.0.1.4")
CLIENT_V6=("fd00::2" "fd00::3" "fd00::4")
CLIENT_UNDERLAY=("10.10.0.11" "10.10.0.12" "10.10.0.13")
BRIDGE="qf523br"
HOST_VETH=("qf523hs" "qf523h1" "qf523h2" "qf523h3")
SERVER_UNDERLAY="10.10.0.1"
GATEWAY_UNDERLAY="10.10.0.254"
TUN_NAME="qtun0"
METRICS_PORT=19523
ADMIN_SOCKET="${QF_E2E_ADMIN_SOCKET:-/tmp/qf523-${$}.sock}"
ADMIN_SOCKET_OWNED=0
BLACK_HOLE_FILTER_ACTIVE=0

PHASE_PIDS=()
CAPTURE_PIDS=()
EGRESS_CAPTURE_PIDS=()

log() { printf '[TODO-523] %s\n' "$*"; }
fail() {
  printf '[TODO-523] FAIL: %s\n' "$*" >&2
  dump_diagnostics
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

wait_for_log_count() {
  local file="$1"
  local pattern="$2"
  local expected="$3"
  local timeout_seconds="$4"
  local attempts=$((timeout_seconds * 5))
  local count=0
  for ((attempt = 0; attempt < attempts; attempt++)); do
    count="$(grep -c "$pattern" "$file" 2>/dev/null || true)"
    if ((count >= expected)); then
      return 0
    fi
    sleep 0.2
  done
  fail "timed out waiting for $expected occurrences of $pattern in $file; found $count"
}

wait_for_socket() {
  local socket_path="$1"
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S "$socket_path" ]] && return 0
    sleep 0.1
  done
  fail "admin socket did not appear: $socket_path"
}

stop_phase_processes() {
  local pid
  for pid in "${CAPTURE_PIDS[@]}" "${PHASE_PIDS[@]}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  for ((attempt = 0; attempt < 20; attempt++)); do
    local alive=0
    for pid in "${CAPTURE_PIDS[@]}" "${PHASE_PIDS[@]}"; do
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        alive=1
      fi
    done
    ((alive == 0)) && break
    sleep 0.1
  done
  for pid in "${CAPTURE_PIDS[@]}" "${PHASE_PIDS[@]}"; do
    [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  PHASE_PIDS=()
  CAPTURE_PIDS=()
  if [[ "$ADMIN_SOCKET_OWNED" == "1" ]]; then
    rm -f -- "$ADMIN_SOCKET"
    ADMIN_SOCKET_OWNED=0
  fi
}

prepare_admin_socket() {
  [[ "$ADMIN_SOCKET" == /* ]] || fail 'QF_E2E_ADMIN_SOCKET must be an absolute path'
  ((${#ADMIN_SOCKET} <= 100)) || fail 'admin socket path exceeds the Unix-domain socket limit'
  [[ ! -e "$ADMIN_SOCKET" ]] || fail "refusing to replace existing admin socket: $ADMIN_SOCKET"
}

cleanup() {
  set +e
  stop_client_egress_capture
  stop_phase_processes
  remove_client_large_datagram_black_hole
  ip netns del "$SERVER_NS" 2>/dev/null
  local ns
  for ns in "${CLIENT_NS[@]}"; do
    ip netns del "$ns" 2>/dev/null
  done
  local host_veth
  for host_veth in "${HOST_VETH[@]}"; do
    ip link del "$host_veth" 2>/dev/null
  done
  ip link del "$BRIDGE" 2>/dev/null
}

dump_diagnostics() {
  set +e
  if ip netns exec "$SERVER_NS" true 2>/dev/null; then
    fetch_metrics throughput-failure || true
  fi
  printf '%s\n' '=== namespaces ===' >&2
  ip netns list >&2
  printf '%s\n' '=== server log tail ===' >&2
  tail -120 "$ARTIFACT_DIR"/server-*.log >&2 2>/dev/null
  printf '%s\n' '=== client log tails ===' >&2
  tail -60 "$ARTIFACT_DIR"/client-*.log >&2 2>/dev/null
  printf '%s\n' '=== server routing state ===' >&2
  ip netns exec "$SERVER_NS" nft list table inet quicfuscate_rt >&2 2>/dev/null
  ip netns exec "$SERVER_NS" iptables -S FORWARD >&2 2>/dev/null
  ip netns exec "$SERVER_NS" ip6tables -S FORWARD >&2 2>/dev/null
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

setup_topology() {
  cleanup
  mkdir -p "$ARTIFACT_DIR"
  prepare_certificate
  sha256sum "$BINARY" >"$ARTIFACT_DIR/binary.sha256"

  ip link add "$BRIDGE" type bridge
  ip addr add "$GATEWAY_UNDERLAY/24" dev "$BRIDGE"
  ip link set "$BRIDGE" up

  setup_namespace_link "$SERVER_NS" "${HOST_VETH[0]}" "$SERVER_UNDERLAY"
  local index
  for index in 0 1 2; do
    setup_namespace_link \
      "${CLIENT_NS[$index]}" \
      "${HOST_VETH[$((index + 1))]}" \
      "${CLIENT_UNDERLAY[$index]}"
  done
}

prepare_certificate() {
  if [[ -n "$CERT" || -n "$KEY" ]]; then
    [[ -n "$CERT" && -n "$KEY" ]] \
      || fail 'QF_E2E_CERT and QF_E2E_KEY must be set together'
    [[ -r "$CERT" && -r "$KEY" ]] \
      || fail 'QF_E2E_CERT or QF_E2E_KEY is unreadable'
    return
  fi

  local leaf_cert="$ARTIFACT_DIR/leaf.crt"
  local certificate_request="$ARTIFACT_DIR/server.csr"
  local certificate_extensions="$ARTIFACT_DIR/leaf-ext.cnf"
  local certificate_serial="$ARTIFACT_DIR/ca.srl"
  CERT="$ARTIFACT_DIR/server.crt"
  KEY="$ARTIFACT_DIR/server.key"

  cat >"$certificate_extensions" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:10.10.0.1
EOF
  openssl req -newkey rsa:2048 -keyout "$KEY" -out "$certificate_request" \
    -nodes -subj '/CN=cdn.cloudflare.com' >/dev/null 2>&1 \
    || fail 'could not generate the isolated server key'
  openssl x509 -req -in "$certificate_request" -CA "$CA" -CAkey "$CA_KEY" \
    -CAserial "$certificate_serial" -CAcreateserial -out "$leaf_cert" -days 365 \
    -extfile "$certificate_extensions" >/dev/null 2>&1 \
    || fail 'could not sign the isolated server certificate'
  cat "$leaf_cert" "$CA" >"$CERT" \
    || fail 'could not assemble the isolated certificate chain'
}

setup_namespace_link() {
  local namespace="$1"
  local host_veth="$2"
  local address="$3"

  ip netns add "$namespace"
  ip link add "$host_veth" type veth peer name eth0 netns "$namespace"
  ip link set "$host_veth" master "$BRIDGE"
  ip link set "$host_veth" up
  ip netns exec "$namespace" ip link set lo up
  ip netns exec "$namespace" ip addr add "$address/24" dev eth0
  ip netns exec "$namespace" ip link set eth0 up
  ip netns exec "$namespace" ip route add default via "$GATEWAY_UNDERLAY"
  ip netns exec "$namespace" sysctl -wq net.ipv4.conf.all.rp_filter=0
  ip netns exec "$namespace" sysctl -wq net.ipv4.conf.default.rp_filter=0
}

issue_qkey() {
  printf '{"cmd":"qkey"}\n' | nc -U "$ADMIN_SOCKET" | python3 -c \
    'import json,sys; response=json.load(sys.stdin); assert response["success"]; print(response["data"]["qkey"])'
}

start_phase() {
  local phase="$1"
  local allow_client_to_client="$2"
  local pmtu_payload_max="$3"
  local tun_mtu_ceiling="$4"
  local probe_interval_ms="${5:-60000}"
  local black_hole_timeout_ms="${6:-10000}"
  stop_phase_processes
  [[ ! -e "$ADMIN_SOCKET" ]] || fail "admin socket appeared before phase start: $ADMIN_SOCKET"
  ADMIN_SOCKET_OWNED=1

  local phase_config="$ARTIFACT_DIR/config-$phase.toml"
  # Transport PMTU is a QUIC UDP-payload limit. 1472 is the largest payload
  # that fits an IPv4 Ethernet path with a 1500-byte L3 MTU (1500 - 20 - 8).
  printf '[transport]\nmtu = %s\nmax_udp_payload = %s\ndisable_pmtud = false\npmtu_min_mtu = 1280\npmtu_max_mtu = %s\npmtu_probe_interval_ms = %s\npmtu_black_hole_timeout_ms = %s\n' \
    "$pmtu_payload_max" "$pmtu_payload_max" "$pmtu_payload_max" "$probe_interval_ms" "$black_hole_timeout_ms" >"$phase_config"

  local server_args=(
    server
    --config "$phase_config"
    --cert "$CERT"
    --key "$KEY"
    --listen "$SERVER_UNDERLAY:4433"
    --admin-socket "$ADMIN_SOCKET"
    --metrics-port "$METRICS_PORT"
    --tun
    --tun-name "$TUN_NAME"
    --tun-mtu "$tun_mtu_ceiling"
    --tun-ip 10.0.1.1
    --tun-netmask 255.255.255.0
    --tun-ip6 fd00::1
    --tun-prefix6 64
    --no-drop-privileges
    -v
  )
  if [[ "$allow_client_to_client" == "1" ]]; then
    server_args+=(--allow-client-to-client)
  fi

  ip netns exec "$SERVER_NS" "$BINARY" "${server_args[@]}" \
    >"$ARTIFACT_DIR/server-$phase.log" 2>&1 &
  PHASE_PIDS+=("$!")
  wait_for_socket "$ADMIN_SOCKET"

  local index qkey client_log
  for index in 0 1 2; do
    qkey="$(issue_qkey)"
    [[ -n "$qkey" ]] || fail "empty QKey for client $((index + 1))"
    client_log="$ARTIFACT_DIR/client-$phase-$((index + 1)).log"
    ip netns exec "${CLIENT_NS[$index]}" "$BINARY" client \
      --config "$phase_config" \
      --remote "$SERVER_UNDERLAY:4433" \
      --url "https://$SERVER_UNDERLAY/" \
      --qkey "$qkey" \
      --ca-file "$CA" \
      --verify-peer \
      --tun \
      --tun-name "$TUN_NAME" \
      --tun-mtu "$tun_mtu_ceiling" \
      --tun-ip "${CLIENT_V4[$index]}" \
      --tun-netmask 255.255.255.0 \
      --tun-ip6 "${CLIENT_V6[$index]}" \
      --tun-prefix6 64 \
      --no-utls \
      -v >"$client_log" 2>&1 &
    PHASE_PIDS+=("$!")
    wait_for_log_count "$client_log" 'TLS handshake complete' 1 20
  done
  wait_for_log_count "$ARTIFACT_DIR/server-$phase.log" 'New client connected:' 3 20
  configure_tun_routes
  verify_unique_addresses
}

configure_tun_routes() {
  ip netns exec "$SERVER_NS" ip link set "$TUN_NAME" up
  ip netns exec "$SERVER_NS" ip route replace 224.0.0.0/4 dev "$TUN_NAME"
  ip netns exec "$SERVER_NS" ip -6 route replace ff00::/8 dev "$TUN_NAME"

  local index
  for index in 0 1 2; do
    ip netns exec "${CLIENT_NS[$index]}" ip link set "$TUN_NAME" up
    ip netns exec "${CLIENT_NS[$index]}" ip route replace 224.0.0.0/4 dev "$TUN_NAME"
    ip netns exec "${CLIENT_NS[$index]}" ip -6 route replace ff00::/8 dev "$TUN_NAME"
  done
}

verify_unique_addresses() {
  local index
  for index in 0 1 2; do
    if ! ip netns exec "${CLIENT_NS[$index]}" ip -j addr show dev "$TUN_NAME" | \
      python3 -c \
        'import json,sys; expected4,expected6=sys.argv[1:]; data=json.load(sys.stdin); addresses={item["local"] for item in data[0]["addr_info"]}; assert expected4 in addresses, (expected4, addresses); assert expected6 in addresses, (expected6, addresses)' \
        "${CLIENT_V4[$index]}" "${CLIENT_V6[$index]}"; then
      fail "client $((index + 1)) TUN addresses were not configured"
    fi
  done
}

wait_for_tunnel_readiness() {
  local phase="$1"
  local index family source destination log_file
  for index in 0 1 2; do
    for family in 4 6; do
      if [[ "$family" == "4" ]]; then
        source="${CLIENT_V4[$index]}"
        destination="10.0.1.1"
      else
        source="${CLIENT_V6[$index]}"
        destination="fd00::1"
      fi
      log_file="$ARTIFACT_DIR/readiness$family-$phase-$((index + 1)).log"
      for ((attempt = 1; attempt <= 10; attempt++)); do
        if ip netns exec "${CLIENT_NS[$index]}" ping "-$family" -c 1 -W 1 -I "$source" \
          "$destination" >>"$log_file" 2>&1; then
          break
        fi
        sleep 0.1
      done
      grep -q ' 0% packet loss' "$log_file" || \
        fail "client $((index + 1)) IPv$family data plane did not become ready"
    done
  done
}

prove_simultaneous_dual_stack() {
  local phase="$1"
  local ping_pids=()
  local index
  for index in 0 1 2; do
    ip netns exec "${CLIENT_NS[$index]}" ping -4 -c 5 -W 3 -I "${CLIENT_V4[$index]}" 10.0.1.1 \
      >"$ARTIFACT_DIR/ping4-$phase-$((index + 1)).log" 2>&1 &
    ping_pids+=("$!")
    ip netns exec "${CLIENT_NS[$index]}" ping -6 -c 5 -W 3 -I "${CLIENT_V6[$index]}" fd00::1 \
      >"$ARTIFACT_DIR/ping6-$phase-$((index + 1)).log" 2>&1 &
    ping_pids+=("$!")
  done

  local pid
  for pid in "${ping_pids[@]}"; do
    wait "$pid" || fail "simultaneous dual-stack ping process failed in phase $phase"
  done
  for index in 0 1 2; do
    grep -q ' 0% packet loss' "$ARTIFACT_DIR/ping4-$phase-$((index + 1)).log" || \
      fail "IPv4 ping loss for client $((index + 1)) in phase $phase"
    grep -q ' 0% packet loss' "$ARTIFACT_DIR/ping6-$phase-$((index + 1)).log" || \
      fail "IPv6 ping loss for client $((index + 1)) in phase $phase"
  done
}

prove_framed_h3_fallback() {
  local output
  output="$(ip netns exec "${CLIENT_NS[0]}" ping -6 -c 3 -W 3 -s 1200 \
    -I "${CLIENT_V6[0]}" fd00::1 2>&1)"
  printf '%s\n' "$output" >"$ARTIFACT_DIR/framed-h3-ipv6.txt"
  grep -q ' 0% packet loss' <<<"$output" || fail 'framed H3 IPv6 fallback lost packets'
  wait_for_log_count "$ARTIFACT_DIR/client-default-1.log" \
    'framed H3 tunnel uplink active' 1 10
  wait_for_log_count "$ARTIFACT_DIR/server-default.log" \
    'framed H3 tunnel downlink active' 1 10
}

prove_client_local_ptb() {
  ip netns exec "${CLIENT_NS[0]}" ip link set "$TUN_NAME" mtu 1500
  ip netns exec "${CLIENT_NS[0]}" ip route replace 198.51.100.2/32 dev "$TUN_NAME"
  ip netns exec "${CLIENT_NS[0]}" ip -6 route replace 2001:db8::2/128 dev "$TUN_NAME"

  local ipv4_output ipv6_output
  ipv4_output="$(ip netns exec "${CLIENT_NS[0]}" ping -4 -c 1 -W 2 -M 'do' -s 1350 \
    -I "${CLIENT_V4[0]}" 198.51.100.2 2>&1 || true)"
  ipv6_output="$(ip netns exec "${CLIENT_NS[0]}" ping -6 -c 1 -W 2 -s 1320 \
    -I "${CLIENT_V6[0]}" 2001:db8::2 2>&1 || true)"
  printf '%s\n' "$ipv4_output" >"$ARTIFACT_DIR/client-local-ptb4.txt"
  printf '%s\n' "$ipv6_output" >"$ARTIFACT_DIR/client-local-ptb6.txt"

  ip netns exec "${CLIENT_NS[0]}" ip link set "$TUN_NAME" mtu 1280
  grep -Eqi 'message too long|mtu[ =]+1280|Frag needed' <<<"$ipv4_output" || \
    fail 'client-local IPv4 PTB response was not observed'
  grep -Eqi 'message too long|mtu[ =]+1280|Packet too big' <<<"$ipv6_output" || \
    fail 'client-local IPv6 PTB response was not observed'
}

prove_dplpmtud_ethernet_1500() {
  local index
  for index in 0 1 2; do
    wait_for_log_count "$ARTIFACT_DIR/client-opt-in-$((index + 1)).log" \
      'DPLPMTUD confirmed path MTU: 1280B -> 1472B' 1 10
  done
  wait_for_log_count "$ARTIFACT_DIR/server-opt-in.log" \
    'DPLPMTUD confirmed path MTU: 1280B -> 1472B' 3 10
}

start_capture() {
  local namespace="$1"
  local name="$2"
  local filter="$3"
  ip netns exec "$namespace" timeout 5 tcpdump -l -nn -Q in -i "$TUN_NAME" "$filter" \
    >"$ARTIFACT_DIR/$name.log" 2>&1 &
  CAPTURE_PIDS+=("$!")
}

start_client_egress_capture() {
  local phase="$1"
  [[ "$EXTERNAL_EGRESS_CAPTURE" == "1" ]] || return 0
  ((${#EGRESS_CAPTURE_PIDS[@]} == 0)) || fail 'external throughput capture already active'

  tcpdump -tt -n -l -Q in -i "${HOST_VETH[1]}" \
    "udp and src host ${CLIENT_UNDERLAY[0]} and dst host $SERVER_UNDERLAY and dst port 4433" \
    >"$ARTIFACT_DIR/egress-$phase.log" 2>&1 &
  EGRESS_CAPTURE_PIDS+=("$!")
  tcpdump -tt -n -l -Q inout -i "${HOST_VETH[0]}" \
    "udp and src host ${CLIENT_UNDERLAY[0]} and dst host $SERVER_UNDERLAY and dst port 4433" \
    >"$ARTIFACT_DIR/server-ingress-$phase.log" 2>&1 &
  EGRESS_CAPTURE_PIDS+=("$!")
  sleep 0.2
  local pid
  for pid in "${EGRESS_CAPTURE_PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null || fail 'external throughput capture did not start'
  done
}

stop_client_egress_capture() {
  local pid
  for pid in "${EGRESS_CAPTURE_PIDS[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
  done
  for pid in "${EGRESS_CAPTURE_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  EGRESS_CAPTURE_PIDS=()
}

summarize_client_egress_capture() {
  local phase="$1"
  [[ "$EXTERNAL_EGRESS_CAPTURE" == "1" ]] || return 0

  python3 "$EGRESS_SUMMARIZER" \
    --capture "$ARTIFACT_DIR/egress-$phase.log" \
    --server-capture "$ARTIFACT_DIR/server-ingress-$phase.log" \
    --trial "$ARTIFACT_DIR/tcp6-client-$phase-1.json" \
    --trial "$ARTIFACT_DIR/tcp6-client-$phase-2.json" \
    --trial "$ARTIFACT_DIR/tcp6-client-$phase-3.json" \
    --output "$ARTIFACT_DIR/egress-$phase-summary.txt" \
    || fail "external client egress capture did not retain enough packets in phase $phase"
}

finish_captures() {
  local pid
  for pid in "${CAPTURE_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  CAPTURE_PIDS=()
}

assert_capture_seen() {
  local name="$1"
  local pattern="$2"
  grep -q "$pattern" "$ARTIFACT_DIR/$name.log" || fail "tcpdump evidence missing: $name / $pattern"
}

assert_capture_absent() {
  local name="$1"
  local pattern="$2"
  if grep -q "$pattern" "$ARTIFACT_DIR/$name.log"; then
    fail "unexpected tcpdump traffic: $name / $pattern"
  fi
}

prove_owned_unicast_isolation() {
  start_capture "${CLIENT_NS[0]}" owned-c1 'icmp and dst host 10.0.1.2'
  start_capture "${CLIENT_NS[1]}" owned-c2 'icmp and dst host 10.0.1.2'
  start_capture "${CLIENT_NS[2]}" owned-c3 'icmp and dst host 10.0.1.2'
  sleep 0.5
  ip netns exec "$SERVER_NS" ping -4 -c 3 -W 3 -I 10.0.1.1 10.0.1.2 >/dev/null
  finish_captures
  assert_capture_seen owned-c1 'ICMP echo request'
  assert_capture_absent owned-c2 'ICMP echo request'
  assert_capture_absent owned-c3 'ICMP echo request'
}

prove_default_deny_and_spoof_rejection() {
  start_capture "${CLIENT_NS[1]}" deny-v4-c2 'icmp and dst host 10.0.1.3'
  start_capture "${CLIENT_NS[1]}" deny-v6-c2 'icmp6 and dst host fd00::3'
  sleep 0.5
  if ip netns exec "${CLIENT_NS[0]}" ping -4 -c 2 -W 1 -I 10.0.1.2 10.0.1.3 >/dev/null 2>&1; then
    fail 'default client-to-client IPv4 policy allowed traffic'
  fi
  if ip netns exec "${CLIENT_NS[0]}" ping -6 -c 2 -W 1 -I fd00::2 fd00::3 >/dev/null 2>&1; then
    fail 'default client-to-client IPv6 policy allowed traffic'
  fi
  finish_captures
  assert_capture_absent deny-v4-c2 'ICMP echo request'
  assert_capture_absent deny-v6-c2 'ICMP6, echo request'

  ip netns exec "${CLIENT_NS[0]}" ip addr add 10.0.1.99/32 dev "$TUN_NAME"
  ip netns exec "${CLIENT_NS[0]}" ip -6 addr add fd00::99/128 dev "$TUN_NAME"
  start_capture "$SERVER_NS" spoof-v4-server 'src host 10.0.1.99'
  start_capture "$SERVER_NS" spoof-v6-server 'src host fd00::99'
  sleep 0.5
  ip netns exec "${CLIENT_NS[0]}" ping -4 -c 2 -W 1 -I 10.0.1.99 10.0.1.1 >/dev/null 2>&1 || true
  ip netns exec "${CLIENT_NS[0]}" ping -6 -c 2 -W 1 -I fd00::99 fd00::1 >/dev/null 2>&1 || true
  finish_captures
  assert_capture_absent spoof-v4-server '10.0.1.99'
  assert_capture_absent spoof-v6-server 'fd00::99'
  ip netns exec "${CLIENT_NS[0]}" ip addr del 10.0.1.99/32 dev "$TUN_NAME"
  ip netns exec "${CLIENT_NS[0]}" ip -6 addr del fd00::99/128 dev "$TUN_NAME"
}

prove_fanout() {
  local index
  for index in 1 2; do
    start_capture "${CLIENT_NS[$index]}" "broadcast-c$((index + 1))" 'icmp and dst host 10.0.1.255'
    start_capture "${CLIENT_NS[$index]}" "multicast4-c$((index + 1))" 'icmp and dst host 224.0.0.1'
    start_capture "${CLIENT_NS[$index]}" "multicast6-c$((index + 1))" 'icmp6 and dst host ff02::1'
  done
  sleep 0.5
  ip netns exec "${CLIENT_NS[0]}" ping -4 -b -c 1 -W 1 -I 10.0.1.2 10.0.1.255 >/dev/null 2>&1 || true
  ip netns exec "${CLIENT_NS[0]}" ping -4 -c 1 -W 1 -I 10.0.1.2 224.0.0.1 >/dev/null 2>&1 || true
  ip netns exec "${CLIENT_NS[0]}" ping -6 -c 1 -W 1 -I fd00::2 'ff02::1%qtun0' >/dev/null 2>&1 || true
  finish_captures
  for index in 1 2; do
    assert_capture_seen "broadcast-c$((index + 1))" 'ICMP echo request'
    assert_capture_seen "multicast4-c$((index + 1))" 'ICMP echo request'
    assert_capture_seen "multicast6-c$((index + 1))" 'ICMP6, echo request'
  done
}

prove_icmp_boundaries() {
  ip netns exec "${CLIENT_NS[0]}" ip route replace 198.51.100.1/32 dev "$TUN_NAME"
  local ttl_output
  ttl_output="$(ip netns exec "${CLIENT_NS[0]}" ping -4 -c 1 -W 2 -t 1 -I 10.0.1.2 198.51.100.1 2>&1 || true)"
  grep -qi 'Time to live exceeded' <<<"$ttl_output" || fail 'IPv4 TTL-expiry response was not observed'

  ip netns exec "$SERVER_NS" ip link add qf523ptb type dummy
  ip netns exec "$SERVER_NS" ip addr add 192.0.2.1/32 dev qf523ptb
  ip netns exec "$SERVER_NS" ip -6 addr add 2001:db8:ffff::1/128 dev qf523ptb nodad
  ip netns exec "$SERVER_NS" ip link set qf523ptb up
  ip netns exec "$SERVER_NS" ip link set "$TUN_NAME" mtu 1500
  ip netns exec "$SERVER_NS" timeout 8 tcpdump -l -nn -vv -i "$TUN_NAME" \
    'icmp or icmp6' \
    >"$ARTIFACT_DIR/icmp-ptb-wire.log" 2>&1 &
  local capture_pid="$!"
  CAPTURE_PIDS+=("$capture_pid")
  sleep 0.5
  local ptb_output ptb6_output
  ptb_output="$(ip netns exec "$SERVER_NS" ping -4 -c 1 -W 2 -M 'do' -s 1350 \
    -I 192.0.2.1 10.0.1.2 2>&1 || true)"
  ptb6_output="$(ip netns exec "$SERVER_NS" ping -6 -c 1 -W 2 -s 1320 \
    -I 2001:db8:ffff::1 fd00::2 2>&1 || true)"
  wait "$capture_pid" 2>/dev/null || true
  CAPTURE_PIDS=()
  fetch_metrics ptb
  ip netns exec "$SERVER_NS" ip link set "$TUN_NAME" mtu 1280
  ip netns exec "$SERVER_NS" ip link del qf523ptb
  printf '%s\n' "$ptb_output" >"$ARTIFACT_DIR/icmp-ptb.txt"
  printf '%s\n' "$ptb6_output" >"$ARTIFACT_DIR/icmp6-ptb.txt"
  grep -q 'need to frag (mtu 1280)' "$ARTIFACT_DIR/icmp-ptb-wire.log" || \
    fail 'IPv4 PTB response was not emitted on the server TUN'
  grep -Eqi 'packet too big.*mtu 1280' "$ARTIFACT_DIR/icmp-ptb-wire.log" || \
    fail 'IPv6 PTB response was not emitted on the server TUN'
  assert_metric_positive ptb packet_too_big
  assert_metric_positive ptb icmpv6
}

fetch_metrics() {
  local phase="$1"
  printf 'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    ip netns exec "$SERVER_NS" nc -w 3 127.0.0.1 "$METRICS_PORT" \
    >"$ARTIFACT_DIR/metrics-$phase.txt"
}

assert_metric_positive() {
  local phase="$1"
  local outcome="$2"
  local line value
  line="$(grep "^quicfuscate_routing_packets_total{outcome=\"$outcome\"}" "$ARTIFACT_DIR/metrics-$phase.txt" || true)"
  [[ -n "$line" ]] || fail "missing routing metric outcome=$outcome"
  value="${line##* }"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value == 0)); then
    fail "routing metric outcome=$outcome is not positive: $value"
  fi
}

assert_metric_zero() {
  local phase="$1"
  local metric="$2"
  local line value
  line="$(grep "^$metric " "$ARTIFACT_DIR/metrics-$phase.txt" || true)"
  [[ -n "$line" ]] || fail "missing metric $metric"
  value="${line##* }"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value != 0)); then
    fail "metric $metric must be zero: $value"
  fi
}

assert_metric_family_zero() {
  local phase="$1"
  local metric="$2"
  local lines line value
  lines="$(grep "^$metric{" "$ARTIFACT_DIR/metrics-$phase.txt" || true)"
  [[ -n "$lines" ]] || fail "missing metric family $metric"
  while IFS= read -r line; do
    value="${line##* }"
    if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value != 0)); then
      fail "metric family $metric must be zero: $line"
    fi
  done <<<"$lines"
}

prove_backpressure_quiescence() {
  local phase="$1"
  fetch_metrics "throughput-$phase"
  assert_metric_zero "throughput-$phase" quicfuscate_tun_downlink_backpressure_pending_packets
  assert_metric_zero "throughput-$phase" quicfuscate_tun_downlink_backpressure_pending_bytes
  assert_metric_family_zero "throughput-$phase" quicfuscate_tun_downlink_backpressure_events_total
  assert_metric_family_zero "throughput-$phase" quicfuscate_masque_downlink_response_events_total
}

prove_routing_metrics() {
  local phase="$1"
  fetch_metrics "$phase"
  local outcome
  for outcome in broadcast multicast drop_spoofed drop_inter_client local unicast fanout packet_too_big time_exceeded icmpv6; do
    assert_metric_positive "$phase" "$outcome"
  done
}

prove_linux_dual_stack_state() {
  [[ "$(ip netns exec "$SERVER_NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || \
    fail 'IPv6 forwarding is not enabled in the server namespace'
  if ip netns exec "$SERVER_NS" nft list table inet quicfuscate_rt \
    >"$ARTIFACT_DIR/routing-nft.txt" 2>/dev/null; then
    grep -q 'ip6 saddr fd00::/64' "$ARTIFACT_DIR/routing-nft.txt" || fail 'nftables IPv6 source prefix missing'
    grep -q 'masquerade' "$ARTIFACT_DIR/routing-nft.txt" || fail 'nftables IPv6 masquerade missing'
  else
    ip netns exec "$SERVER_NS" ip6tables -t nat -S POSTROUTING >"$ARTIFACT_DIR/routing-ip6tables.txt"
    grep -q -- '-s fd00::/64' "$ARTIFACT_DIR/routing-ip6tables.txt" || fail 'ip6tables IPv6 source prefix missing'
    grep -q -- '-j MASQUERADE' "$ARTIFACT_DIR/routing-ip6tables.txt" || fail 'ip6tables IPv6 masquerade missing'
  fi
}

prove_ipv6_throughput() {
  local phase="$1"
  local trial port server_pid before_snapshot after_snapshot summary
  for trial in 1 2 3; do
    port=$((5524 + trial))
    before_snapshot="$ARTIFACT_DIR/server-udp-$phase-$trial-before.json"
    after_snapshot="$ARTIFACT_DIR/server-udp-$phase-$trial-after.json"
    summary="$ARTIFACT_DIR/server-udp-$phase-$trial-summary.txt"
    ip netns exec "$SERVER_NS" python3 "$UDP_SOCKET_EVIDENCE" snapshot \
      --port 4433 --output "$before_snapshot" || \
      fail "could not capture server UDP socket before IPv6 throughput trial $trial in phase $phase"
    ip netns exec "$SERVER_NS" timeout "$((THROUGHPUT_TRIAL_SECONDS + 20))" \
      python3 "$THROUGHPUT_PROBE" server \
      --bind fd00::1 --port "$port" --timeout "$((THROUGHPUT_TRIAL_SECONDS + 15))" \
      --result "$ARTIFACT_DIR/tcp6-server-$phase-$trial.json" \
      >"$ARTIFACT_DIR/tcp6-server-$phase-$trial.log" 2>&1 &
    server_pid="$!"
    if ! ip netns exec "${CLIENT_NS[0]}" timeout "$((THROUGHPUT_TRIAL_SECONDS + 20))" \
      python3 "$THROUGHPUT_PROBE" client \
      --source fd00::2 --destination fd00::1 --port "$port" \
      --duration "$THROUGHPUT_TRIAL_SECONDS" --rate-bps "$THROUGHPUT_RATE_BPS" \
      --timeout "$((THROUGHPUT_TRIAL_SECONDS + 15))" \
      --result "$ARTIFACT_DIR/tcp6-client-$phase-$trial.json"; then
      ip netns exec "$SERVER_NS" python3 "$UDP_SOCKET_EVIDENCE" snapshot \
        --port 4433 --output "$after_snapshot" || true
      python3 "$UDP_SOCKET_EVIDENCE" verify \
        --before "$before_snapshot" --after "$after_snapshot" --output "$summary" || true
      kill -TERM "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      fail "IPv6 throughput trial $trial did not terminate successfully in phase $phase"
    fi
    if ! wait "$server_pid"; then
      ip netns exec "$SERVER_NS" python3 "$UDP_SOCKET_EVIDENCE" snapshot \
        --port 4433 --output "$after_snapshot" || true
      python3 "$UDP_SOCKET_EVIDENCE" verify \
        --before "$before_snapshot" --after "$after_snapshot" --output "$summary" || true
      fail "IPv6 throughput receiver failed in phase $phase trial $trial"
    fi
    ip netns exec "$SERVER_NS" python3 "$UDP_SOCKET_EVIDENCE" snapshot \
      --port 4433 --output "$after_snapshot" || \
      fail "could not capture server UDP socket after IPv6 throughput trial $trial in phase $phase"
    python3 "$UDP_SOCKET_EVIDENCE" verify \
      --before "$before_snapshot" --after "$after_snapshot" --output "$summary" || \
      fail "server UDP socket dropped datagrams during IPv6 throughput trial $trial in phase $phase"
  done
  python3 -c \
    'import json,pathlib,statistics,sys; duration=float(sys.argv[4]); trials=[json.load(open(path, encoding="utf-8")) for path in sys.argv[5:]]; receiver=[trial["receiver"] for trial in trials]; valid=all(trial["bytes_sent"] > 0 and trial["bytes_sent"] == item["bytes"] and trial["sha256"] == item["sha256"] and item["elapsed_seconds"] > 0 and trial["receiver_bits_per_second"] > 0 for trial,item in zip(trials,receiver)); valid=valid and all(duration * 0.95 <= trial["elapsed_seconds"] <= duration + 5 for trial in trials); assert valid, trials; values=[trial["receiver_bits_per_second"] for trial in trials]; median=statistics.median(values); minimum=min(values); summary=f"IPv6 receiver-verified TCP throughput ({sys.argv[1]}) trials: {values[0] / 1_000_000:.3f}, {values[1] / 1_000_000:.3f}, {values[2] / 1_000_000:.3f} Mbit/s; median: {median / 1_000_000:.3f} Mbit/s; minimum trial: {minimum / 1_000_000:.3f} Mbit/s"; pathlib.Path(sys.argv[2]).write_text(f"{median}\n", encoding="utf-8"); pathlib.Path(sys.argv[3]).write_text(f"{summary}\n", encoding="utf-8"); print(summary)' \
    "$phase" "$ARTIFACT_DIR/throughput-$phase.bps" "$ARTIFACT_DIR/throughput-$phase-samples.txt" \
    "$THROUGHPUT_TRIAL_SECONDS" \
    "$ARTIFACT_DIR/tcp6-client-$phase-1.json" \
    "$ARTIFACT_DIR/tcp6-client-$phase-2.json" \
    "$ARTIFACT_DIR/tcp6-client-$phase-3.json"
}

prove_pmtu_efficiency_gain() {
  python3 -c \
    'import pathlib,sys; floor=float(pathlib.Path(sys.argv[1]).read_text()); ceiling=float(pathlib.Path(sys.argv[2]).read_text()); gain=(ceiling/floor)-1.0; print(f"DPLPMTUD throughput gain: {gain * 100:.2f}% ({floor / 1_000_000:.3f} -> {ceiling / 1_000_000:.3f} Mbit/s)"); assert gain >= 0.15, gain' \
    "$ARTIFACT_DIR/throughput-default.bps" "$ARTIFACT_DIR/throughput-opt-in.bps" \
    >"$ARTIFACT_DIR/throughput-comparison.txt" || \
    fail '1472-byte QUIC UDP payload did not retain the required 15% gain over the safe 1280-byte floor'
  cat "$ARTIFACT_DIR/throughput-comparison.txt"
}

install_client_large_datagram_black_hole() {
  ip netns exec "${CLIENT_NS[0]}" tc qdisc add dev eth0 clsact
  ip netns exec "${CLIENT_NS[0]}" tc filter add dev eth0 egress protocol ip priority 1 \
    basic match 'cmp(u16 at 2 layer network gt 1308)' action drop
  BLACK_HOLE_FILTER_ACTIVE=1
  ip netns exec "${CLIENT_NS[0]}" tc -s filter show dev eth0 egress \
    >"$ARTIFACT_DIR/black-hole-rule-installed.txt"
}

remove_client_large_datagram_black_hole() {
  if [[ "$BLACK_HOLE_FILTER_ACTIVE" == "1" ]]; then
    ip netns exec "${CLIENT_NS[0]}" tc qdisc del dev eth0 clsact 2>/dev/null || true
    BLACK_HOLE_FILTER_ACTIVE=0
  fi
}

prove_dplpmtud_black_hole_recovery() {
  local client_log="$ARTIFACT_DIR/client-opt-in-1.log"
  install_client_large_datagram_black_hole

  ip netns exec "$SERVER_NS" timeout 45 python3 "$THROUGHPUT_PROBE" server \
    --bind fd00::1 --port 5524 --timeout 35 \
    --result "$ARTIFACT_DIR/tcp6-server-black-hole.json" \
    >"$ARTIFACT_DIR/tcp6-server-black-hole.log" 2>&1 &
  local server_pid="$!"
  ip netns exec "${CLIENT_NS[0]}" timeout 30 python3 "$THROUGHPUT_PROBE" client \
    --source fd00::2 --destination fd00::1 --port 5524 --duration 20 \
    --rate-bps "$THROUGHPUT_RATE_BPS" --timeout 25 \
    --result "$ARTIFACT_DIR/tcp6-client-black-hole.json" &
  local client_pid="$!"
  local detection_started="$SECONDS"

  wait_for_log_count "$client_log" \
    'DPLPMTUD black hole detected: path MTU 1472B -> 1280B' 1 12
  local detection_seconds=$((SECONDS - detection_started))
  ((detection_seconds <= 12)) || fail "black-hole detection exceeded timeout envelope: ${detection_seconds}s"

  # Retain the loss boundary after reset so successful transfer progress proves
  # the 1280-byte fallback, then restore the path for periodic upward re-probe.
  sleep 8
  remove_client_large_datagram_black_hole
  ip netns exec "${CLIENT_NS[0]}" tc qdisc show dev eth0 \
    >"$ARTIFACT_DIR/black-hole-rule-removed.txt"

  if ! wait "$client_pid"; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    fail 'IPv6 transfer did not recover across the black-hole interval'
  fi
  wait "$server_pid" || fail 'IPv6 black-hole recovery receiver failed'
  python3 -c \
    'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); received=data["receiver"]; valid=data["bytes_sent"] == received["bytes"] and data["sha256"] == received["sha256"] and received["bytes"] > 65536 and received["elapsed_seconds"] >= 18; assert valid, data; print("Black-hole recovery transfer: {} bytes in {:.3f}s".format(received["bytes"], received["elapsed_seconds"]))' \
    "$ARTIFACT_DIR/tcp6-client-black-hole.json" \
    >"$ARTIFACT_DIR/black-hole-transfer.txt" || fail 'black-hole recovery transfer evidence invalid'
  wait_for_log_count "$client_log" \
    'DPLPMTUD confirmed path MTU: .*B -> 1472B' 2 15
  cat "$ARTIFACT_DIR/black-hole-transfer.txt"
  printf 'Black-hole detection: %ss\n' "$detection_seconds" \
    >"$ARTIFACT_DIR/black-hole-detection.txt"
}

prove_client_unicast_opt_in() {
  local output
  output="$(ip netns exec "${CLIENT_NS[0]}" ping -4 -c 5 -W 3 -I 10.0.1.2 10.0.1.3 2>&1)"
  grep -q ' 0% packet loss' <<<"$output" || fail 'explicit IPv4 client-unicast opt-in failed'
  output="$(ip netns exec "${CLIENT_NS[0]}" ping -6 -c 5 -W 3 -I fd00::2 fd00::3 2>&1)"
  grep -q ' 0% packet loss' <<<"$output" || fail 'explicit IPv6 client-unicast opt-in failed'
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || fail 'this proof requires Linux network namespaces'
  [[ "${EUID:-$(id -u)}" == "0" ]] || fail 'this proof requires root'
  local command
  for command in flock ip iptables nc openssl ping python3 sha256sum sysctl tc tcpdump timeout; do
    require_command "$command"
  done
  if ! command -v nft >/dev/null 2>&1; then
    require_command iptables
    require_command ip6tables
  fi
  [[ -x "$BINARY" ]] || fail "release binary not executable: $BINARY"
  [[ -r "$THROUGHPUT_PROBE" ]] || fail "TCP throughput probe is unreadable: $THROUGHPUT_PROBE"
  [[ -r "$EGRESS_SUMMARIZER" ]] || fail "external egress summarizer is unreadable: $EGRESS_SUMMARIZER"
  [[ -r "$UDP_SOCKET_EVIDENCE" ]] || fail "UDP socket evidence helper is unreadable: $UDP_SOCKET_EVIDENCE"
  if [[ ! "$THROUGHPUT_TRIAL_SECONDS" =~ ^[0-9]+$ ]] \
    || ((THROUGHPUT_TRIAL_SECONDS < 5)); then
    fail 'QF_E2E_THROUGHPUT_TRIAL_SECONDS must be an integer of at least 5'
  fi
  if [[ ! "$THROUGHPUT_RATE_BPS" =~ ^[0-9]+$ ]] \
    || ((THROUGHPUT_RATE_BPS < 1000000)); then
    fail 'QF_E2E_THROUGHPUT_RATE_BPS must be an integer of at least 1000000'
  fi
  [[ "$EXTERNAL_EGRESS_CAPTURE" == "0" || "$EXTERNAL_EGRESS_CAPTURE" == "1" ]] || \
    fail 'QF_E2E_EXTERNAL_EGRESS_CAPTURE must be 0 or 1'
  [[ -r "$CA" && -r "$CA_KEY" ]] || fail 'CA certificate or key fixture is unreadable'

  exec 9>"$LOCK_FILE"
  flock -w "$LOCK_TIMEOUT" 9 || fail "could not acquire E2E lock within ${LOCK_TIMEOUT}s"
  prepare_admin_socket
  setup_topology

  log 'phase 1: default-deny multi-client dual-stack policy'
  start_phase default 0 1280 1280
  wait_for_tunnel_readiness default
  prove_framed_h3_fallback
  prove_client_local_ptb
  prove_simultaneous_dual_stack default
  prove_owned_unicast_isolation
  prove_default_deny_and_spoof_rejection
  prove_fanout
  prove_icmp_boundaries
  prove_routing_metrics default
  prove_linux_dual_stack_state
  start_client_egress_capture default
  prove_ipv6_throughput default
  stop_client_egress_capture
  summarize_client_egress_capture default
  prove_backpressure_quiescence default

  log 'phase 2: explicit client-unicast opt-in'
  start_phase opt-in 1 1472 1500 1000 2000
  wait_for_tunnel_readiness opt-in
  prove_dplpmtud_ethernet_1500
  prove_simultaneous_dual_stack opt-in
  prove_client_unicast_opt_in
  start_client_egress_capture opt-in
  prove_ipv6_throughput opt-in
  stop_client_egress_capture
  summarize_client_egress_capture opt-in
  prove_pmtu_efficiency_gain
  prove_dplpmtud_black_hole_recovery
  prove_backpressure_quiescence opt-in

  log "PASS: complete evidence retained in $ARTIFACT_DIR"
}

main "$@"
