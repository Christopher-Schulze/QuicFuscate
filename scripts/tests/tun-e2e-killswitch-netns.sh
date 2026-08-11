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
HEARTBEAT_TIMEOUT_MS="${HEARTBEAT_TIMEOUT_MS:-15000}"
TRANSITION_LIMIT_MS="$((HEARTBEAT_TIMEOUT_MS + 100))"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
SERVER_LOG="/tmp/qf-killswitch-server.log"
CLIENT_LOG="/tmp/qf-killswitch-client.log"
CAPTURE_FILE="/tmp/qf-killswitch-underlay.pcap"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-auto}"
RUNTIME_PATH="${RUNTIME_PATH:-$PATH}"
EXPECT_BACKEND_UNAVAILABLE="${EXPECT_BACKEND_UNAVAILABLE:-0}"
RUNTIME_CONFIG="$CERT_DIR/runtime.toml"
RUNTIME_CONFIG_ARGS=()

case "$FIREWALL_BACKEND" in
  auto | nftables)
    RULE_BACKEND="nftables"
    ;;
  iptables)
    RULE_BACKEND="iptables"
    ;;
  *)
    echo "invalid FIREWALL_BACKEND: $FIREWALL_BACKEND" >&2
    exit 2
    ;;
esac
if [ "$EXPECT_BACKEND_UNAVAILABLE" = "1" ] && [ "$FIREWALL_BACKEND" = "auto" ]; then
  echo "EXPECT_BACKEND_UNAVAILABLE requires an explicit FIREWALL_BACKEND" >&2
  exit 2
fi

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

for command in flock ip nft openssl nc python3 dig ping sha256sum tcpdump; do
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
  local process_state
  if ! kill -0 "$1" 2>/dev/null; then
    return 0
  fi
  if ! read -r _ _ process_state _ <"/proc/$1/stat"; then
    return 0
  fi
  [ "$process_state" = "Z" ]
}

assert_selection_log() {
  local log_file="$1"
  local expected_line
  expected_line="Firewall backend selected: requested=$FIREWALL_BACKEND, selected=$RULE_BACKEND"
  wait_for 5 grep -q "$expected_line" "$log_file"
  if [ "$(grep -c 'Firewall backend selected:' "$log_file")" != "1" ]; then
    echo "firewall backend was not resolved exactly once: $log_file" >&2
    exit 1
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    grep -q \
      "$expected_line, nftables_available=false, iptables_available=true" \
      "$log_file"
  else
    grep -q "$expected_line, nftables_available=true," "$log_file"
  fi
}

rules_contain() {
  local rules
  rules="$(kill_switch_rules)"
  grep -q -- "$1" <<<"$rules"
}

table_absent() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    ! ip netns exec "$CLIENT_NS" nft list table inet quicfuscate_ks >/dev/null 2>&1
  else
    ! ip netns exec "$CLIENT_NS" iptables -S QUICFUSCATE_KS >/dev/null 2>&1 &&
      ! ip netns exec "$CLIENT_NS" ip6tables -S QUICFUSCATE_KS >/dev/null 2>&1
  fi
}

endpoint_rule_absent() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    ! rules_contain "udp dport $LISTEN_PORT accept"
  else
    ! ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -d "$SERVER_UNDERLAY_IP" \
      -p udp --dport "$LISTEN_PORT" -j ACCEPT >/dev/null 2>&1
  fi
}

kill_switch_rules() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    ip netns exec "$CLIENT_NS" nft list table inet quicfuscate_ks
  else
    ip netns exec "$CLIENT_NS" iptables -S OUTPUT
    ip netns exec "$CLIENT_NS" iptables -S QUICFUSCATE_KS
    ip netns exec "$CLIENT_NS" ip6tables -S OUTPUT
    ip netns exec "$CLIENT_NS" ip6tables -S QUICFUSCATE_KS
  fi
}

connected_tun_rule_present() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    rules_contain 'oifname "qtun0" accept'
  else
    ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -o qtun0 -j ACCEPT >/dev/null 2>&1 &&
      ip netns exec "$CLIENT_NS" ip6tables \
        -C QUICFUSCATE_KS -o qtun0 -j ACCEPT >/dev/null 2>&1
  fi
}

block_policy_present() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    rules_contain 'policy drop'
  else
    ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -j DROP >/dev/null 2>&1 &&
      ip netns exec "$CLIENT_NS" ip6tables \
        -C QUICFUSCATE_KS -j DROP >/dev/null 2>&1
  fi
}

routing_policy_absent() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    ! ip netns exec "$SERVER_NS" nft list table inet quicfuscate_rt >/dev/null 2>&1
  else
    ! ip netns exec "$SERVER_NS" iptables -S QUICFUSCATE_RT >/dev/null 2>&1 &&
      ! ip netns exec "$SERVER_NS" iptables -t nat -S QUICFUSCATE_NAT >/dev/null 2>&1 &&
      ! ip netns exec "$SERVER_NS" ip6tables -S QUICFUSCATE_RT >/dev/null 2>&1 &&
      ! ip netns exec "$SERVER_NS" ip6tables -t nat -S QUICFUSCATE_NAT >/dev/null 2>&1
  fi
}

create_runtime_config() {
  if [ "$FIREWALL_BACKEND" = "auto" ]; then
    return
  fi
  printf '%s\n' \
    '[security.firewall]' \
    "backend = \"$FIREWALL_BACKEND\"" >"$RUNTIME_CONFIG"
  RUNTIME_CONFIG_ARGS=(--config "$RUNTIME_CONFIG")
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
  ip netns exec "$SERVER_NS" ip route replace default via "$CLIENT_UNDERLAY_IP" dev qf-ks-srv-veth
  ip netns exec "$CLIENT_NS" ip route replace default via "$SERVER_UNDERLAY_IP" dev qf-ks-cli-veth
}

seed_unrelated_firewall_state() {
  local namespace program
  if [ "$RULE_BACKEND" = "nftables" ]; then
    for namespace in "$SERVER_NS" "$CLIENT_NS"; do
      ip netns exec "$namespace" nft add table inet qf_unrelated_probe
      ip netns exec "$namespace" nft add chain inet qf_unrelated_probe retained
      ip netns exec "$namespace" nft add rule inet qf_unrelated_probe retained counter
    done
    return
  fi

  for namespace in "$SERVER_NS" "$CLIENT_NS"; do
    for program in iptables ip6tables; do
      ip netns exec "$namespace" "$program" -N QF_UNRELATED_PROBE
      ip netns exec "$namespace" "$program" -A QF_UNRELATED_PROBE -j RETURN
    done
  done
}

unrelated_firewall_fingerprint() {
  local namespace program
  if [ "$RULE_BACKEND" = "nftables" ]; then
    for namespace in "$SERVER_NS" "$CLIENT_NS"; do
      ip netns exec "$namespace" nft -s list table inet qf_unrelated_probe
    done
  else
    for namespace in "$SERVER_NS" "$CLIENT_NS"; do
      for program in iptables ip6tables; do
        ip netns exec "$namespace" "$program" -S QF_UNRELATED_PROBE
      done
    done
  fi | sha256sum | cut -d' ' -f1
}

assert_unrelated_firewall_unchanged() {
  local after
  after="$(unrelated_firewall_fingerprint)"
  if [ "$after" != "$UNRELATED_FIREWALL_FINGERPRINT" ]; then
    echo "unrelated firewall state changed: before=$UNRELATED_FIREWALL_FINGERPRINT after=$after" >&2
    exit 1
  fi
}

assert_atomic_replacement_failure() {
  if [ "$RULE_BACKEND" = "nftables" ]; then
    local initial_rules invalid_rules rules_before rules_after status
    initial_rules='table inet quicfuscate_ks {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
  }
}'
    invalid_rules='delete table inet quicfuscate_ks
table inet quicfuscate_ks {
  chain output {
    type filter hook output priority 0; policy drop;
    definitely-invalid-statement
  }
}'
    ip netns exec "$CLIENT_NS" nft -f - <<<"$initial_rules"
    rules_before="$(ip netns exec "$CLIENT_NS" nft -s list table inet quicfuscate_ks)"
    set +e
    ip netns exec "$CLIENT_NS" nft -f - <<<"$invalid_rules" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      echo "invalid nftables replacement unexpectedly succeeded" >&2
      exit 1
    fi
    rules_after="$(ip netns exec "$CLIENT_NS" nft -s list table inet quicfuscate_ks)"
    if [ "$rules_before" != "$rules_after" ]; then
      echo "failed nftables replacement changed the owned table" >&2
      exit 1
    fi
    ip netns exec "$CLIENT_NS" nft delete table inet quicfuscate_ks
    return
  fi

  local program restore_program initial_rules invalid_rules rules_before rules_after status
  for program in iptables ip6tables; do
    if [ "$program" = "iptables" ]; then
      restore_program="iptables-restore"
    else
      restore_program="ip6tables-restore"
    fi
    initial_rules='*filter
:QUICFUSCATE_KS - [0:0]
-A QUICFUSCATE_KS -o lo -j ACCEPT
-A QUICFUSCATE_KS -j DROP
-I OUTPUT 1 -j QUICFUSCATE_KS
COMMIT'
    invalid_rules='*filter
:QUICFUSCATE_KS - [0:0]
-A QUICFUSCATE_KS --definitely-invalid
COMMIT'
    ip netns exec "$CLIENT_NS" "$restore_program" --noflush --wait 5 <<<"$initial_rules"
    rules_before="$(
      ip netns exec "$CLIENT_NS" "$program" -S OUTPUT
      ip netns exec "$CLIENT_NS" "$program" -S QUICFUSCATE_KS
    )"
    set +e
    ip netns exec "$CLIENT_NS" "$restore_program" --noflush --wait 5 \
      <<<"$invalid_rules" >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      echo "invalid $restore_program replacement unexpectedly succeeded" >&2
      exit 1
    fi
    rules_after="$(
      ip netns exec "$CLIENT_NS" "$program" -S OUTPUT
      ip netns exec "$CLIENT_NS" "$program" -S QUICFUSCATE_KS
    )"
    if [ "$rules_before" != "$rules_after" ]; then
      echo "failed $restore_program replacement changed the owned chain" >&2
      exit 1
    fi
    ip netns exec "$CLIENT_NS" "$program" -D OUTPUT -j QUICFUSCATE_KS
    ip netns exec "$CLIENT_NS" "$program" -F QUICFUSCATE_KS
    ip netns exec "$CLIENT_NS" "$program" -X QUICFUSCATE_KS
  done
}

start_server() {
  rm -f /tmp/qf-killswitch-admin.sock "$SERVER_LOG"
  ip netns exec "$SERVER_NS" env PATH="$RUNTIME_PATH" "$BINARY" server \
    "${RUNTIME_CONFIG_ARGS[@]}" \
    --cert "$CERT_DIR/server.crt" --key "$CERT_DIR/server.key" \
    --listen "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
    --admin-socket /tmp/qf-killswitch-admin.sock \
    --tun --tun-name qtun0 --tun-ip "$SERVER_TUN_IP" \
    --tun-netmask 255.255.255.0 --no-drop-privileges -v \
    >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  wait_for 10 test -S /tmp/qf-killswitch-admin.sock
  assert_selection_log "$SERVER_LOG"
  if [ "$RULE_BACKEND" = "nftables" ]; then
    ip netns exec "$SERVER_NS" nft list table inet quicfuscate_rt >/dev/null
  else
    ip netns exec "$SERVER_NS" iptables -S QUICFUSCATE_RT >/dev/null
    ip netns exec "$SERVER_NS" iptables -t nat -S QUICFUSCATE_NAT >/dev/null
    ip netns exec "$SERVER_NS" ip6tables -S QUICFUSCATE_RT >/dev/null
    ip netns exec "$SERVER_NS" ip6tables -t nat -S QUICFUSCATE_NAT >/dev/null
    ip netns exec "$SERVER_NS" iptables \
      -C FORWARD -j QUICFUSCATE_RT >/dev/null
    ip netns exec "$SERVER_NS" iptables \
      -t nat -C POSTROUTING -j QUICFUSCATE_NAT >/dev/null
    ip netns exec "$SERVER_NS" ip6tables \
      -C FORWARD -j QUICFUSCATE_RT >/dev/null
    ip netns exec "$SERVER_NS" ip6tables \
      -t nat -C POSTROUTING -j QUICFUSCATE_NAT >/dev/null
  fi
}

fetch_qkey() {
  printf '%s\n' '{"cmd":"qkey"}' | nc -U /tmp/qf-killswitch-admin.sock | \
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["qkey"])'
}

start_client() {
  local qkey="$1"
  rm -f "$CLIENT_LOG"
  ip netns exec "$CLIENT_NS" env PATH="$RUNTIME_PATH" "$BINARY" client \
    "${RUNTIME_CONFIG_ARGS[@]}" \
    --remote "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
    --url "https://$SERVER_UNDERLAY_IP/" --qkey "$qkey" \
    --ca-file "$CERT_DIR/ca.crt" --verify-peer --disable-doh --no-utls \
    --tun --tun-name qtun0 --kill-switch \
    --vpn-dns "$SERVER_TUN_IP" \
    --heartbeat-timeout-ms "$HEARTBEAT_TIMEOUT_MS" -v \
    >"$CLIENT_LOG" 2>&1 &
  CLIENT_PID=$!
  wait_for 15 grep -q 'TLS handshake complete' "$CLIENT_LOG"
  assert_selection_log "$CLIENT_LOG"
  wait_for 10 connected_tun_rule_present
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

assert_connected_policy() {
  local rules
  if [ "$RULE_BACKEND" = "nftables" ]; then
    rules="$(kill_switch_rules)"
    grep -q "ip daddr $SERVER_UNDERLAY_IP udp dport $LISTEN_PORT accept" <<<"$rules"
    grep -q "oifname \"qtun0\" ip daddr $SERVER_TUN_IP udp dport 53 accept" <<<"$rules"
    grep -q 'udp dport 53 drop' <<<"$rules"
    grep -q 'tcp dport 53 drop' <<<"$rules"
    grep -q 'oifname "qtun0" accept' <<<"$rules"
  else
    ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -d "$SERVER_UNDERLAY_IP" \
      -p udp --dport "$LISTEN_PORT" -j ACCEPT
    ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -o qtun0 -d "$SERVER_TUN_IP" \
      -p udp --dport 53 -j ACCEPT
    ip netns exec "$CLIENT_NS" iptables \
      -C QUICFUSCATE_KS -o qtun0 -d "$SERVER_TUN_IP" \
      -p tcp --dport 53 -j ACCEPT
    for program in iptables ip6tables; do
      ip netns exec "$CLIENT_NS" "$program" \
        -C QUICFUSCATE_KS -p udp --dport 53 -j DROP
      ip netns exec "$CLIENT_NS" "$program" \
        -C QUICFUSCATE_KS -p tcp --dport 53 -j DROP
      ip netns exec "$CLIENT_NS" "$program" \
        -C QUICFUSCATE_KS -o qtun0 -j ACCEPT
    done
  fi
}

assert_dns_and_ipv6_policy() {
  local capture_filter
  capture_filter="(src host $CLIENT_UNDERLAY_IP or src host $CLIENT_UNDERLAY_IP6) and (port 53 or ip6)"
  rm -f "$CAPTURE_FILE"
  ip netns exec "$CLIENT_NS" tcpdump -i qf-ks-cli-veth -nn -U \
    -w "$CAPTURE_FILE" "$capture_filter" >/dev/null 2>&1 &
  CAPTURE_PID=$!
  sleep 0.5
  if ! kill -0 "$CAPTURE_PID" 2>/dev/null || [ ! -s "$CAPTURE_FILE" ]; then
    echo "underlay capture failed to start" >&2
    exit 1
  fi

  ip netns exec "$CLIENT_NS" ping -c 3 -W 2 "$SERVER_TUN_IP" \
    >/tmp/qf-killswitch-tun-ping.log
  ip netns exec "$CLIENT_NS" dig @"$SERVER_TUN_IP" example.com A \
    +tries=1 +time=1 +norecurse +stats >/tmp/qf-killswitch-vpn-dns.log || true
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
  ip netns exec "$CLIENT_NS" ping -c 1 -W 2 "$SERVER_TUN_IP" >/dev/null
  start_ms="$(date +%s%3N)"
  kill -STOP "$SERVER_PID"
  wait_for 17 grep -q 'heartbeat timeout' "$CLIENT_LOG"
  wait_for 2 endpoint_rule_absent
  end_ms="$(date +%s%3N)"
  elapsed_ms="$((end_ms - start_ms))"
  if [ "$elapsed_ms" -lt "$((HEARTBEAT_TIMEOUT_MS - 100))" ]; then
    echo "fail-closed transition preceded the configured timeout: ${elapsed_ms}ms" >&2
    exit 1
  fi
  if [ "$elapsed_ms" -gt "$TRANSITION_LIMIT_MS" ]; then
    echo "fail-closed transition took ${elapsed_ms}ms, limit ${TRANSITION_LIMIT_MS}ms" >&2
    exit 1
  fi
  wait_for 5 process_exited "$CLIENT_PID"
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""
  block_policy_present
  if connected_tun_rule_present; then
    echo "TUN allow rule survived unexpected loss" >&2
    exit 1
  fi
  kill -9 "$SERVER_PID"
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  if ip netns exec "$CLIENT_NS" ping -c 1 -W 1 "$SERVER_UNDERLAY_IP" >/dev/null 2>&1; then
    echo "underlay traffic escaped after unexpected loss" >&2
    exit 1
  fi
  echo "unexpected-loss transition: ${elapsed_ms}ms"
}

assert_stale_cleanup() {
  ip netns exec "$CLIENT_NS" env PATH="$RUNTIME_PATH" "$BINARY" client \
    "${RUNTIME_CONFIG_ARGS[@]}" \
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
  kill -TERM "$SERVER_PID"
  wait_for 5 process_exited "$SERVER_PID"
  wait "$SERVER_PID"
  SERVER_PID=""
  wait_for 5 routing_policy_absent
}

assert_requested_backend_unavailable() {
  set +e
  ip netns exec "$SERVER_NS" env PATH="$RUNTIME_PATH" "$BINARY" server \
    "${RUNTIME_CONFIG_ARGS[@]}" \
    --cert "$CERT_DIR/server.crt" --key "$CERT_DIR/server.key" \
    --listen "$SERVER_UNDERLAY_IP:$LISTEN_PORT" \
    --admin-socket /tmp/qf-killswitch-admin.sock \
    --tun --tun-name qtun0 --tun-ip "$SERVER_TUN_IP" \
    --tun-netmask 255.255.255.0 --no-drop-privileges -v \
    >"$SERVER_LOG" 2>&1
  local status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "unavailable explicit backend unexpectedly started" >&2
    exit 1
  fi
  grep -q \
    "Firewall backend selection failed: requested=$FIREWALL_BACKEND, selected=none" \
    "$SERVER_LOG"
  grep -q "requested firewall backend $FIREWALL_BACKEND is unavailable" "$SERVER_LOG"
  routing_policy_absent
  table_absent
  echo "PASS ($FIREWALL_BACKEND unavailable): explicit selection failed closed before firewall state"
}

create_certificates
create_runtime_config
setup_namespaces
seed_unrelated_firewall_state
UNRELATED_FIREWALL_FINGERPRINT="$(unrelated_firewall_fingerprint)"
if [ "$EXPECT_BACKEND_UNAVAILABLE" = "1" ]; then
  assert_requested_backend_unavailable
  assert_unrelated_firewall_unchanged
  exit 0
fi
assert_atomic_replacement_failure
start_server
QKEY="$(fetch_qkey)"
start_client "$QKEY"
require_runtime_owned_tun_assignment "$SERVER_NS" "$SERVER_TUN_IP"
require_runtime_owned_tun_assignment "$CLIENT_NS" "$CLIENT_TUN_IP"
assert_connected_policy
assert_dns_and_ipv6_policy
assert_unexpected_loss_retains_block
assert_stale_cleanup
assert_clean_signal_cleanup
assert_unrelated_firewall_unchanged

echo "PASS ($RULE_BACKEND): connected TUN/DNS policy, IPv6 blocking, ${TRANSITION_LIMIT_MS}ms loss bound, retained fail-closed state, stale cleanup, client/server SIGTERM cleanup, and unchanged unrelated firewall fingerprint $UNRELATED_FIREWALL_FINGERPRINT"
