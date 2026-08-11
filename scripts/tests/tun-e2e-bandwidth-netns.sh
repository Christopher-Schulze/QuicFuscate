#!/usr/bin/env bash
# Three-client production data-plane proof for TODO-529.
#
# Proves unlimited throughput, exact 10-Mbit/s rate enforcement, configured
# burst capacity, terminal UTC quota enforcement, equal-weight fairness, and
# 1:2:1 weighted downlink service through authenticated QUIC/TUN sessions.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/lib-common.sh"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="${QF_E2E_CA:-$PROJECT_ROOT/config/local/ca.crt}"
CA_KEY="${QF_E2E_CA_KEY:-$PROJECT_ROOT/config/local/ca.key}"
CERT="${QF_E2E_CERT:-}"
KEY="${QF_E2E_KEY:-}"
EVIDENCE_ROOT="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-todo529-$$}"
ARTIFACT_DIR=""
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
UDP_PROBE="$SCRIPT_DIR/utils/udp-throughput-probe.py"

SERVER_NS="qf529s"
CLIENT_NS=("qf529c1" "qf529c2" "qf529c3")
CLIENT_V4=("10.29.0.2" "10.29.0.3" "10.29.0.4")
CLIENT_V6=("fd29::2" "fd29::3" "fd29::4")
CLIENT_UNDERLAY=("10.29.10.11" "10.29.10.12" "10.29.10.13")
HOST_VETH=("qf529hs" "qf529h1" "qf529h2" "qf529h3")
SERVER_UNDERLAY="10.29.10.1"
GATEWAY_UNDERLAY="10.29.10.254"
BRIDGE="qf529br"
TUN_NAME="qtun0"
ADMIN_SOCKET="${QF_E2E_ADMIN_SOCKET:-/tmp/qf529-${$}.sock}"
ADMIN_PORT=19529
METRICS_PORT=19530
ADMIN_USER="todo529"
ADMIN_PASSWORD="todo529-isolated-proof"
CSRF_TOKEN=""
PHASE_PIDS=()
MEASUREMENT_PIDS=()
MEASUREMENT_INDEX=0
ADMIN_REQUEST_INDEX=0
TOPOLOGY_OWNED=0
SERVER_DOWNLINK_RATE_BYTES_PER_SECOND=0
SERVER_DOWNLINK_BURST_BYTES=0
RUNTIME_LOG_ARGS=()
RUNTIME_LOG_MODE="info"

log() { printf '[TODO-529] %s\n' "$*"; }
fail() {
  printf '[TODO-529] FAIL: %s\n' "$*" >&2
  dump_diagnostics
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

stop_measurements() {
  local pid
  for pid in "${MEASUREMENT_PIDS[@]}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${MEASUREMENT_PIDS[@]}"; do
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  MEASUREMENT_PIDS=()
}

cleanup() {
  set +e
  stop_measurements
  local pid namespace host_veth
  for pid in "${PHASE_PIDS[@]}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${PHASE_PIDS[@]}"; do
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  if [[ "$TOPOLOGY_OWNED" == "1" ]]; then
    ip netns del "$SERVER_NS" 2>/dev/null
    for namespace in "${CLIENT_NS[@]}"; do
      ip netns del "$namespace" 2>/dev/null
    done
    for host_veth in "${HOST_VETH[@]}"; do
      ip link del "$host_veth" 2>/dev/null
    done
    ip link del "$BRIDGE" 2>/dev/null
    rm -f -- "$ADMIN_SOCKET"
  fi
}

reset_topology_state() {
  cleanup
  set -Eeuo pipefail
  PHASE_PIDS=()
  MEASUREMENT_PIDS=()
  TOPOLOGY_OWNED=0
  CSRF_TOKEN=""
}

prove_topology_absent() {
  local namespace link
  for namespace in "$SERVER_NS" "${CLIENT_NS[@]}"; do
    if ip netns exec "$namespace" true >/dev/null 2>&1; then
      fail "network namespace survived cleanup: $namespace"
    fi
  done
  for link in "$BRIDGE" "${HOST_VETH[@]}"; do
    if ip link show "$link" >/dev/null 2>&1; then
      fail "network link survived cleanup: $link"
    fi
  done
  [[ ! -e "$ADMIN_SOCKET" ]] || fail "admin socket survived cleanup: $ADMIN_SOCKET"
}

dump_diagnostics() {
  set +e
  printf '%s\n' '=== namespaces ===' >&2
  ip netns list >&2
  printf '%s\n' '=== server log ===' >&2
  tail -160 "$ARTIFACT_DIR/server.log" >&2 2>/dev/null
  printf '%s\n' '=== client logs ===' >&2
  tail -80 "$ARTIFACT_DIR"/client-*.log >&2 2>/dev/null
  printf '%s\n' '=== latest measurements ===' >&2
  tail -80 "$ARTIFACT_DIR"/*summary.json >&2 2>/dev/null
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_file() {
  local path="$1"
  local label="$2"
  for ((attempt = 0; attempt < 150; attempt++)); do
    [[ -e "$path" ]] && return 0
    sleep 0.1
  done
  fail "$label did not appear: $path"
}

wait_for_log_count() {
  local path="$1"
  local pattern="$2"
  local expected="$3"
  for ((attempt = 0; attempt < 150; attempt++)); do
    local count
    count="$(grep -c "$pattern" "$path" 2>/dev/null || true)"
    ((count >= expected)) && return 0
    sleep 0.2
  done
  fail "timed out waiting for $expected occurrences of $pattern in $path"
}

prepare_certificate() {
  if [[ -n "$CERT" || -n "$KEY" ]]; then
    [[ -n "$CERT" && -n "$KEY" && -r "$CERT" && -r "$KEY" ]] \
      || fail 'QF_E2E_CERT and QF_E2E_KEY must name readable files together'
    return
  fi

  local request="$ARTIFACT_DIR/server.csr"
  local leaf="$ARTIFACT_DIR/leaf.crt"
  local extensions="$ARTIFACT_DIR/leaf-ext.cnf"
  CERT="$ARTIFACT_DIR/server.crt"
  KEY="$ARTIFACT_DIR/server.key"
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:cdn.cloudflare.com,DNS:localhost,IP:10.29.10.1' \
    >"$extensions"
  openssl req -newkey rsa:2048 -keyout "$KEY" -out "$request" \
    -nodes -subj '/CN=cdn.cloudflare.com' >/dev/null 2>&1 \
    || fail 'could not generate isolated server key'
  openssl x509 -req -in "$request" -CA "$CA" -CAkey "$CA_KEY" \
    -CAcreateserial -CAserial "$ARTIFACT_DIR/ca.srl" -out "$leaf" -days 7 \
    -extfile "$extensions" >/dev/null 2>&1 \
    || fail 'could not sign isolated server certificate'
  cp "$leaf" "$CERT"
  printf '\n' >>"$CERT"
  sed -n '1,$p' "$CA" >>"$CERT"
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
}

setup_topology() {
  [[ ! -e "$ARTIFACT_DIR" ]] || fail "refusing to replace artifact directory: $ARTIFACT_DIR"
  [[ ! -e "$ADMIN_SOCKET" ]] || fail "refusing to replace admin socket: $ADMIN_SOCKET"
  mkdir -p "$ARTIFACT_DIR/web"
  printf '<!doctype html><title>TODO-529</title>\n' >"$ARTIFACT_DIR/web/index.html"
  printf 'rate_bytes_per_second=%s\nburst_bytes=%s\n' \
    "$SERVER_DOWNLINK_RATE_BYTES_PER_SECOND" \
    "$SERVER_DOWNLINK_BURST_BYTES" \
    >"$ARTIFACT_DIR/downlink-scheduler-policy.env"
  printf 'runtime_log_mode=%s\n' "$RUNTIME_LOG_MODE" >"$ARTIFACT_DIR/runtime-log-mode.env"
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

preflight_topology() {
  local namespace link
  for namespace in "$SERVER_NS" "${CLIENT_NS[@]}"; do
    if ip netns exec "$namespace" true >/dev/null 2>&1; then
      fail "refusing to replace existing network namespace: $namespace"
    fi
  done
  for link in "$BRIDGE" "${HOST_VETH[@]}"; do
    if ip link show "$link" >/dev/null 2>&1; then
      fail "refusing to replace existing network link: $link"
    fi
  done
}

issue_qkey() {
  printf '{"cmd":"qkey"}\n' | nc -U "$ADMIN_SOCKET" | python3 -c \
    'import json,sys; response=json.load(sys.stdin); assert response["success"]; print(response["data"]["qkey"])'
}

require_runtime_owned_tun_assignment() {
  local namespace="$1"
  local expected_ipv4="$2"
  local expected_ipv6="$3"
  if ! ip netns exec "$namespace" ip -j addr show dev "$TUN_NAME" | python3 -c \
    'import json,sys; expected4,expected6=sys.argv[1:]; data=json.load(sys.stdin); assert len(data)==1,data; link=data[0]; addresses={(item["family"],item["local"],item["prefixlen"]) for item in link["addr_info"]}; assert ("inet",expected4,24) in addresses,(expected4,addresses); assert ("inet6",expected6,64) in addresses,(expected6,addresses); assert link["mtu"]==1280,link; assert "UP" in link["flags"],link' \
    "$expected_ipv4" "$expected_ipv6"; then
    fail "runtime-owned TUN assignment is incomplete in $namespace"
  fi
}

start_runtime() {
  local config="$ARTIFACT_DIR/config.toml"
  printf '%s\n' \
    '[transport]' \
    'cc_algorithm = "reno"' \
    'mtu = 1280' \
    'max_udp_payload = 1280' \
    'disable_pmtud = true' \
    'pmtu_min_mtu = 1280' \
    'pmtu_max_mtu = 1280' \
    '' \
    '[fec]' \
    'mode = "off"' \
    >"$config"

  ip netns exec "$SERVER_NS" env \
    QUICFUSCATE_SERVER_DOWNLINK_RATE_BYTES_PER_SECOND="$SERVER_DOWNLINK_RATE_BYTES_PER_SECOND" \
    QUICFUSCATE_SERVER_DOWNLINK_BURST_BYTES="$SERVER_DOWNLINK_BURST_BYTES" \
    "$BINARY" server \
    --config "$config" \
    --cert "$CERT" \
    --key "$KEY" \
    --listen "$SERVER_UNDERLAY:4433" \
    --admin-socket "$ADMIN_SOCKET" \
    --admin-web "127.0.0.1:$ADMIN_PORT" \
    --admin-web-root "$ARTIFACT_DIR/web" \
    --admin-web-user "$ADMIN_USER" \
    --admin-web-password "$ADMIN_PASSWORD" \
    --qkey-store "$ARTIFACT_DIR/qkeys.json" \
    --metrics-port "$METRICS_PORT" \
    --tun \
    --tun-name "$TUN_NAME" \
    --tun-mtu 1280 \
    --tun-ip 10.29.0.1 \
    --tun-netmask 255.255.255.0 \
    --tun-ip6 fd29::1 \
    --tun-prefix6 64 \
    --no-drop-privileges \
    "${RUNTIME_LOG_ARGS[@]}" >"$ARTIFACT_DIR/server.log" 2>&1 &
  PHASE_PIDS+=("$!")
  wait_for_file "$ADMIN_SOCKET" 'admin socket'
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ip netns exec "$SERVER_NS" curl --silent --fail \
      "http://127.0.0.1:$ADMIN_PORT/api/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  ip netns exec "$SERVER_NS" curl --silent --fail \
    "http://127.0.0.1:$ADMIN_PORT/api/health" >/dev/null \
    || fail 'admin web server did not become ready'

  local index qkey
  for index in 0 1 2; do
    qkey="$(issue_qkey)"
    [[ -n "$qkey" ]] || fail "empty QKey for client $((index + 1))"
    ip netns exec "${CLIENT_NS[$index]}" "$BINARY" client \
      --config "$config" \
      --remote "$SERVER_UNDERLAY:4433" \
      --url "https://$SERVER_UNDERLAY/" \
      --qkey "$qkey" \
      --ca-file "$CA" \
      --verify-peer \
      --disable-doh \
      --tun \
      --tun-name "$TUN_NAME" \
      --no-utls \
      "${RUNTIME_LOG_ARGS[@]}" >"$ARTIFACT_DIR/client-$((index + 1)).log" 2>&1 &
    PHASE_PIDS+=("$!")
    wait_for_log_count "$ARTIFACT_DIR/client-$((index + 1)).log" \
      'TLS handshake complete' 1
  done
  wait_for_log_count "$ARTIFACT_DIR/server.log" 'New client connected:' 3

  require_runtime_owned_tun_assignment "$SERVER_NS" 10.29.0.1 fd29::1
  for index in 0 1 2; do
    require_runtime_owned_tun_assignment \
      "${CLIENT_NS[$index]}" "${CLIENT_V4[$index]}" "${CLIENT_V6[$index]}"
    for ((attempt = 0; attempt < 20; attempt++)); do
      if ip netns exec "${CLIENT_NS[$index]}" ping -6 -c 1 -W 1 \
        -I "${CLIENT_V6[$index]}" fd29::1 >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
    ip netns exec "${CLIENT_NS[$index]}" ping -6 -c 1 -W 2 \
      -I "${CLIENT_V6[$index]}" fd29::1 >/dev/null \
      || fail "client $((index + 1)) data plane is not ready"
  done
}

admin_login() {
  local headers="$ARTIFACT_DIR/admin-login.headers"
  local body="$ARTIFACT_DIR/admin-login.json"
  local status
  status="$(ip netns exec "$SERVER_NS" curl --silent --show-error \
    --dump-header "$headers" \
    --cookie-jar "$ARTIFACT_DIR/admin.cookies" \
    --output "$body" \
    --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --data "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "http://127.0.0.1:$ADMIN_PORT/api/login")"
  [[ "$status" == "200" ]] || fail "admin login returned HTTP $status"
  CSRF_TOKEN="$(python3 -c \
    'import sys; lines=open(sys.argv[1], encoding="utf-8").read().splitlines(); values=[line.split(":",1)[1].strip() for line in lines if line.lower().startswith("x-csrf-token:")]; assert len(values)==1; print(values[0])' \
    "$headers")"
  [[ -n "$CSRF_TOKEN" ]] || fail 'admin login did not return a CSRF token'
}

admin_post() {
  local path="$1"
  local payload="$2"
  ADMIN_REQUEST_INDEX=$((ADMIN_REQUEST_INDEX + 1))
  local output="$ARTIFACT_DIR/admin-post-$ADMIN_REQUEST_INDEX.json"
  local status
  status="$(ip netns exec "$SERVER_NS" curl --silent --show-error \
    --cookie "$ARTIFACT_DIR/admin.cookies" \
    --output "$output" \
    --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --header "Origin: http://127.0.0.1:$ADMIN_PORT" \
    --header "X-CSRF-Token: $CSRF_TOKEN" \
    --header "X-CSRF-Nonce: todo529-$ADMIN_REQUEST_INDEX" \
    --data "$payload" \
    "http://127.0.0.1:$ADMIN_PORT$path")"
  [[ "$status" == "200" ]] || fail "admin POST $path returned HTTP $status"
  python3 -c \
    'import json,sys; response=json.load(open(sys.argv[1], encoding="utf-8")); assert response["success"], response' \
    "$output" || fail "admin POST $path returned an unsuccessful response"
}

set_policy() {
  local index="$1"
  local rate="$2"
  local burst="$3"
  local daily="$4"
  local monthly="$5"
  local weight="$6"
  local payload
  payload="$(printf '{"rate_bytes_per_second":%s,"burst_bytes":%s,"daily_quota_bytes":%s,"monthly_quota_bytes":%s,"weight":%s}' \
    "$rate" "$burst" "$daily" "$monthly" "$weight")"
  admin_post "/api/clients/${CLIENT_V4[$index]}/bandwidth" "$payload"
  admin_post "/api/clients/${CLIENT_V4[$index]}/quota/reset" '{}'
}

set_policies() {
  local rate="$1"
  local burst="$2"
  local daily="$3"
  local monthly="$4"
  shift 4
  local index
  for index in 0 1 2; do
    set_policy "$index" "$rate" "$burst" "$daily" "$monthly" "${1}"
    shift
  done
}

capture_bandwidth_stats() {
  local phase="$1"
  local rate="$2"
  local burst="$3"
  local daily="$4"
  local monthly="$5"
  shift 5
  local index output
  for index in 0 1 2; do
    output="$ARTIFACT_DIR/$phase-bandwidth-$((index + 1)).json"
    ip netns exec "$SERVER_NS" curl --silent --show-error --fail \
      --cookie "$ARTIFACT_DIR/admin.cookies" \
      --header "Origin: http://127.0.0.1:$ADMIN_PORT" \
      "http://127.0.0.1:$ADMIN_PORT/api/clients/${CLIENT_V4[$index]}/bandwidth" \
      --output "$output"
    python3 -c \
      'import json,sys; response=json.load(open(sys.argv[1], encoding="utf-8")); expected={"rate_bytes_per_second":int(sys.argv[2]),"burst_bytes":int(sys.argv[3]),"daily_quota_bytes":int(sys.argv[4]),"monthly_quota_bytes":int(sys.argv[5]),"weight":int(sys.argv[6])}; assert response["success"], response; actual=response["data"]["bandwidth"]["policy"]; assert actual == expected, {"actual":actual,"expected":expected}' \
      "$output" "$rate" "$burst" "$daily" "$monthly" "${1}"
    shift
  done
}

run_downlink_matrix() {
  local phase="$1"
  local duration="$2"
  local offered_rate="$3"
  MEASUREMENT_INDEX=$((MEASUREMENT_INDEX + 1))
  local port_base=$((25000 + MEASUREMENT_INDEX * 10))
  local receiver_duration
  receiver_duration="$(python3 -c 'import sys; print(float(sys.argv[1]) + 1.0)' "$duration")"
  local index
  for index in 0 1 2; do
    ip netns exec "${CLIENT_NS[$index]}" python3 "$UDP_PROBE" receiver \
      --bind "${CLIENT_V6[$index]}" \
      --port "$((port_base + index))" \
      --duration "$receiver_duration" \
      --result "$ARTIFACT_DIR/$phase-receiver-$((index + 1)).json" &
    MEASUREMENT_PIDS+=("$!")
  done
  sleep 0.3
  for index in 0 1 2; do
    ip netns exec "$SERVER_NS" python3 "$UDP_PROBE" sender \
      --source fd29::1 \
      --destination "${CLIENT_V6[$index]}" \
      --port "$((port_base + index))" \
      --duration "$duration" \
      --rate-bps "$offered_rate" \
      --result "$ARTIFACT_DIR/$phase-sender-$((index + 1)).json" &
    MEASUREMENT_PIDS+=("$!")
  done
  local pid
  for pid in "${MEASUREMENT_PIDS[@]}"; do
    wait "$pid" || fail "measurement process failed in phase $phase"
  done
  MEASUREMENT_PIDS=()
  local summary_document
  summary_document="$(python3 -c \
    'import json,sys; phase=sys.argv[1]; duration=float(sys.argv[2]); paths=sys.argv[4:]; samples=[json.load(open(path, encoding="utf-8")) for path in paths]; rates=[item["payload_bytes"]*8.0/duration for item in samples]; result={"phase":phase,"duration_seconds":duration,"offered_rate_bps":float(sys.argv[3]),"payload_rates_bps":rates,"payload_bytes":[item["payload_bytes"] for item in samples],"packets":[item["packets"] for item in samples]}; print(json.dumps(result,sort_keys=True))' \
    "$phase" "$duration" "$offered_rate" \
    "$ARTIFACT_DIR/$phase-receiver-1.json" \
    "$ARTIFACT_DIR/$phase-receiver-2.json" \
    "$ARTIFACT_DIR/$phase-receiver-3.json")" \
    || fail "could not summarize parallel downlink phase $phase"
  qf_json_write_raw_file "$ARTIFACT_DIR/$phase-summary.json" "$summary_document" \
    || fail "could not write parallel downlink summary $phase"
}

run_sequential_downlink_matrix() {
  local phase="$1"
  local duration="$2"
  local offered_rate="$3"
  MEASUREMENT_INDEX=$((MEASUREMENT_INDEX + 1))
  local port_base=$((25000 + MEASUREMENT_INDEX * 10))
  local receiver_duration
  receiver_duration="$(python3 -c 'import sys; print(float(sys.argv[1]) + 1.0)' "$duration")"
  local index receiver_pid sender_pid
  for index in 0 1 2; do
    ip netns exec "${CLIENT_NS[$index]}" python3 "$UDP_PROBE" receiver \
      --bind "${CLIENT_V6[$index]}" \
      --port "$((port_base + index))" \
      --duration "$receiver_duration" \
      --result "$ARTIFACT_DIR/$phase-receiver-$((index + 1)).json" &
    receiver_pid="$!"
    MEASUREMENT_PIDS+=("$receiver_pid")
    sleep 0.3
    ip netns exec "$SERVER_NS" python3 "$UDP_PROBE" sender \
      --source fd29::1 \
      --destination "${CLIENT_V6[$index]}" \
      --port "$((port_base + index))" \
      --duration "$duration" \
      --rate-bps "$offered_rate" \
      --result "$ARTIFACT_DIR/$phase-sender-$((index + 1)).json" &
    sender_pid="$!"
    MEASUREMENT_PIDS+=("$sender_pid")
    wait "$sender_pid" || fail "sender failed for client $((index + 1)) in phase $phase"
    wait "$receiver_pid" || fail "receiver failed for client $((index + 1)) in phase $phase"
    MEASUREMENT_PIDS=()
  done
  local summary_document
  summary_document="$(python3 -c \
    'import json,sys; phase=sys.argv[1]; duration=float(sys.argv[2]); paths=sys.argv[4:]; samples=[json.load(open(path, encoding="utf-8")) for path in paths]; rates=[item["payload_bytes"]*8.0/duration for item in samples]; result={"phase":phase,"duration_seconds":duration,"offered_rate_bps":float(sys.argv[3]),"measurement_mode":"sequential","payload_rates_bps":rates,"payload_bytes":[item["payload_bytes"] for item in samples],"packets":[item["packets"] for item in samples]}; print(json.dumps(result,sort_keys=True))' \
    "$phase" "$duration" "$offered_rate" \
    "$ARTIFACT_DIR/$phase-receiver-1.json" \
    "$ARTIFACT_DIR/$phase-receiver-2.json" \
    "$ARTIFACT_DIR/$phase-receiver-3.json")" \
    || fail "could not summarize sequential downlink phase $phase"
  qf_json_write_raw_file "$ARTIFACT_DIR/$phase-summary.json" "$summary_document" \
    || fail "could not write sequential downlink summary $phase"
}

assert_matrix() {
  local phase="$1"
  local gate="$2"
  python3 -c \
    'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); rates=data["payload_rates_bps"]; gate=sys.argv[2]; passed={"unlimited": min(rates)>=5_000_000 and max(rates)/min(rates)<=1.35, "ten-megabit": min(rates)>=8_000_000 and max(rates)<=10_800_000, "burst": min(rates)>=12_000_000 and max(rates)<=35_000_000, "quota": min(rates)>=5_500_000 and max(rates)<=6_800_000, "weighted": rates[0]>0 and rates[2]>0 and 1.5<=rates[1]/rates[0]<=2.5 and 1.5<=rates[1]/rates[2]<=2.5 and 0.75<=rates[0]/rates[2]<=1.33}[gate]; assert passed, data' \
    "$ARTIFACT_DIR/$phase-summary.json" "$gate" \
    || fail "throughput assertion failed for phase $phase"
}

fetch_metrics() {
  printf 'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    ip netns exec "$SERVER_NS" nc -w 3 127.0.0.1 "$METRICS_PORT" \
    >"$ARTIFACT_DIR/metrics.txt"
}

prove_runtime_clean() {
  if grep -EH 'heartbeat timeout|InternalError|TUN packet send failed' \
    "$ARTIFACT_DIR/server.log" "$ARTIFACT_DIR"/client-*.log \
    >"$ARTIFACT_DIR/runtime-errors.txt"; then
    fail 'runtime logs contain a liveness or transport failure'
  fi
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || fail 'this proof requires Linux network namespaces'
  [[ "${EUID:-$(id -u)}" == "0" ]] || fail 'this proof requires root'
  local command
  for command in curl flock grep ip nc openssl ping python3 sha256sum sysctl timeout; do
    require_command "$command"
  done
  [[ -x "$BINARY" ]] || fail "release binary not executable: $BINARY"
  [[ -r "$UDP_PROBE" ]] || fail "UDP throughput probe is unreadable: $UDP_PROBE"
  [[ -r "$CA" && -r "$CA_KEY" ]] || fail 'CA certificate or key fixture is unreadable'
  [[ "$ADMIN_SOCKET" == /* && ${#ADMIN_SOCKET} -le 100 ]] \
    || fail 'admin socket must be absolute and fit the Unix socket path limit'
  case "${QF_E2E_VERBOSE:-0}" in
    0 | false)
      ;;
    1 | true)
      RUNTIME_LOG_ARGS=(-v)
      RUNTIME_LOG_MODE="verbose"
      ;;
    *)
      fail 'QF_E2E_VERBOSE must be 0, 1, false, or true'
      ;;
  esac

  exec 9>"$LOCK_FILE"
  flock -w "$LOCK_TIMEOUT" 9 || fail "could not acquire E2E lock within ${LOCK_TIMEOUT}s"
  [[ ! -e "$EVIDENCE_ROOT" ]] \
    || fail "refusing to replace evidence root: $EVIDENCE_ROOT"
  ARTIFACT_DIR="$EVIDENCE_ROOT/baseline"
  preflight_topology
  TOPOLOGY_OWNED=1
  setup_topology
  start_runtime
  admin_login

  log 'unlimited equal-weight matrix'
  set_policies 0 0 0 0 1 1 1
  capture_bandwidth_stats unlimited-before 0 0 0 0 1 1 1
  run_downlink_matrix unlimited 5 30000000
  assert_matrix unlimited unlimited

  log 'exact 10-Mbit/s per-client matrix'
  set_policies 1250000 125000 0 0 1 1 1
  capture_bandwidth_stats ten-megabit-before 1250000 125000 0 0 1 1 1
  run_downlink_matrix ten-megabit 8 30000000
  assert_matrix ten-megabit ten-megabit

  log 'configured burst matrix'
  set_policies 1250000 2500000 0 0 1 1 1
  capture_bandwidth_stats burst-before 1250000 2500000 0 0 1 1 1
  run_sequential_downlink_matrix burst 1.5 40000000
  assert_matrix burst burst

  log 'terminal daily quota matrix'
  set_policies 0 0 2400000 0 1 1 1
  capture_bandwidth_stats quota-before 0 0 2400000 0 1 1 1
  run_downlink_matrix quota 3 30000000
  capture_bandwidth_stats quota-after 0 0 2400000 0 1 1 1
  assert_matrix quota quota
  fetch_metrics
  grep -Eq '^quicfuscate_bandwidth_denials_total\{direction="downlink",outcome="daily_quota_exceeded"\} [1-9][0-9]*$' \
    "$ARTIFACT_DIR/metrics.txt" || fail 'daily quota denial metric is missing'

  prove_runtime_clean
  reset_topology_state
  prove_topology_absent

  ARTIFACT_DIR="$EVIDENCE_ROOT/weighted"
  SERVER_DOWNLINK_RATE_BYTES_PER_SECOND=2000000
  SERVER_DOWNLINK_BURST_BYTES=24000
  preflight_topology
  TOPOLOGY_OWNED=1
  setup_topology
  start_runtime
  admin_login

  log 'weighted 1:2:1 downlink fairness matrix'
  set_policies 0 0 0 0 1 2 1
  capture_bandwidth_stats weighted-before 0 0 0 0 1 2 1
  run_downlink_matrix weighted-1-2-1 5 100000000
  assert_matrix weighted-1-2-1 weighted

  prove_runtime_clean
  reset_topology_state
  prove_topology_absent
  log "PASS: complete evidence retained in $EVIDENCE_ROOT"
}

main "$@"
