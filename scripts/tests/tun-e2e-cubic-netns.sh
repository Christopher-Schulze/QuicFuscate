#!/usr/bin/env bash
# CUBIC conformance performance proof for TODO-535.
#
# Uses one exact release binary for two controlled experiments:
# 1. Concurrent CUBIC and Reno UDP payload flows through one shared drop-tail
#    underlay bottleneck, with Jain fairness above 0.8 and no starvation.
# 2. CUBIC with matched Auto-FEC and FEC-off runs on the same fixed-rate path,
#    each comparing a clean baseline against controlled 5% random underlay
#    loss. The artifact reports absolute and relative policy differences; it
#    does not claim a FEC advantage without the recorded control result.
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
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-todo535-$$}"
PERFORMANCE_SAMPLER="$PROJECT_ROOT/scripts/tests/utils/runtime-performance-sampler.py"
LOSS_TRIALS=3
LOSS_RATE_PERCENT=5
MIN_RETAINED_RATIO=0.5
MIN_RETAINED_PERCENT=50
METRICS_PORT=9535
MAX_CPU_ONE_CORE_PERCENT="${QF_E2E_MAX_CPU_ONE_CORE_PERCENT:-50}"
MAX_PEAK_RSS_BYTES="${QF_E2E_MAX_PEAK_RSS_BYTES:-402653184}"
MAX_FALLBACK_ALLOCATIONS="${QF_E2E_MAX_FALLBACK_ALLOCATIONS:-75000}"
MAX_CLEAN_P95_LATENCY_MS="${QF_E2E_MAX_CLEAN_P95_LATENCY_MS:-75}"
MAX_IMPAIRED_P95_LATENCY_MS="${QF_E2E_MAX_IMPAIRED_P95_LATENCY_MS:-100}"

SERVER_NS="qf535s"
CLIENT_NS=("qf535c1" "qf535c2")
CLIENT_TUN_IP=("10.0.1.2" "10.0.1.3")
CLIENT_UNDERLAY=("10.10.0.11" "10.10.0.12")
SERVER_UNDERLAY="10.10.0.1"
GATEWAY_UNDERLAY="10.10.0.254"
BRIDGE="qf535br"
SERVER_HOST_VETH="qf535hs"
CLIENT_HOST_VETH=("qf535h1" "qf535h2")
TUN_NAME="qtun0"
ADMIN_SOCKET="${QF_E2E_ADMIN_SOCKET:-/tmp/qf535-${$}.sock}"
ADMIN_SOCKET_OWNED=0
TOPOLOGY_OWNED=0
STACK_PIDS=()
UDP_RECEIVER_PID=""
PERFORMANCE_SAMPLER_PID=""
PERFORMANCE_SAMPLER_OUTPUT=""

log() { printf '[TODO-535] %s\n' "$*"; }
fail() {
  printf '[TODO-535] FAIL: %s\n' "$*" >&2
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
  local attempts="${4:-100}"
  local count
  for ((attempt = 0; attempt < attempts; attempt++)); do
    count="$(grep -c "$pattern" "$file" 2>/dev/null || true)"
    ((count >= expected)) && return 0
    sleep 0.2
  done
  fail "timed out waiting for $expected occurrences of $pattern in $file"
}

wait_for_socket() {
  for ((attempt = 0; attempt < 100; attempt++)); do
    [[ -S "$ADMIN_SOCKET" ]] && return 0
    sleep 0.1
  done
  fail "admin socket did not appear: $ADMIN_SOCKET"
}

wait_for_metrics() {
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ip netns exec "$SERVER_NS" nc -z 127.0.0.1 "$METRICS_PORT" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  fail "metrics endpoint did not become ready on port $METRICS_PORT"
}

wait_for_tun() {
  local namespace="$1"
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ip netns exec "$namespace" ip link show "$TUN_NAME" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  fail "TUN interface $TUN_NAME did not appear in namespace $namespace"
}

stop_stack() {
  if [[ -n "$PERFORMANCE_SAMPLER_PID" ]]; then
    kill -TERM "$PERFORMANCE_SAMPLER_PID" 2>/dev/null || true
    wait "$PERFORMANCE_SAMPLER_PID" 2>/dev/null || true
    PERFORMANCE_SAMPLER_PID=""
    PERFORMANCE_SAMPLER_OUTPUT=""
  fi
  local pid
  for pid in "${STACK_PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${STACK_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  STACK_PIDS=()
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
  stop_stack
  [[ "$TOPOLOGY_OWNED" == "1" ]] || return
  tc qdisc del dev "$SERVER_HOST_VETH" root 2>/dev/null
  ip netns del "$SERVER_NS" 2>/dev/null
  ip netns del "${CLIENT_NS[0]}" 2>/dev/null
  ip netns del "${CLIENT_NS[1]}" 2>/dev/null
  ip link del "$BRIDGE" 2>/dev/null
  TOPOLOGY_OWNED=0
}

dump_diagnostics() {
  set +e
  printf '%s\n' '=== qdisc ===' >&2
  tc -s qdisc show dev "$SERVER_HOST_VETH" >&2 2>/dev/null
  printf '%s\n' '=== namespaces ===' >&2
  ip netns list >&2
  printf '%s\n' '=== server logs ===' >&2
  tail -100 "$ARTIFACT_DIR"/server-*.log >&2 2>/dev/null
  printf '%s\n' '=== client logs ===' >&2
  tail -80 "$ARTIFACT_DIR"/client-*.log >&2 2>/dev/null
}

prove_runtime_logs_clean() {
  local pattern='panic|Crypto error: crypto failure|AEAD limit reached|Key update error|heartbeat timeout|InternalError|TUN packet send failed'
  if grep -EHi "$pattern" "$ARTIFACT_DIR"/client-*.log "$ARTIFACT_DIR"/server-*.log \
    >"$ARTIFACT_DIR/runtime-liveness-errors.txt"; then
    fail 'runtime logs contain a panic, decryption, heartbeat, InternalError, or TUN send failure'
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  mkdir "$ARTIFACT_DIR"
  TOPOLOGY_OWNED=1
  prepare_certificate
  ip link add "$BRIDGE" type bridge
  ip addr add "$GATEWAY_UNDERLAY/24" dev "$BRIDGE"
  ip link set "$BRIDGE" up
  setup_namespace_link "$SERVER_NS" "$SERVER_HOST_VETH" "$SERVER_UNDERLAY"
  setup_namespace_link "${CLIENT_NS[0]}" "${CLIENT_HOST_VETH[0]}" "${CLIENT_UNDERLAY[0]}"
  setup_namespace_link "${CLIENT_NS[1]}" "${CLIENT_HOST_VETH[1]}" "${CLIENT_UNDERLAY[1]}"
  sha256sum "$BINARY" >"$ARTIFACT_DIR/binary.sha256"
}

preflight_owned_resources() {
  [[ "$ARTIFACT_DIR" == /* ]] || fail 'QF_E2E_ARTIFACT_DIR must be an absolute path'
  [[ ! -e "$ARTIFACT_DIR" ]] \
    || fail "refusing to overwrite existing artifact path: $ARTIFACT_DIR"
  [[ -d "$(dirname "$ARTIFACT_DIR")" ]] \
    || fail "artifact parent directory does not exist: $(dirname "$ARTIFACT_DIR")"
  pgrep -x quicfuscate >/dev/null \
    && fail 'a pre-existing quicfuscate process is running; refusing broad cleanup'
  local namespace
  for namespace in "$SERVER_NS" "${CLIENT_NS[@]}"; do
    ip netns list | grep -Eq "^${namespace}([[:space:]]|$)" \
      && fail "network namespace already exists: $namespace"
  done
  local link
  for link in "$BRIDGE" "$SERVER_HOST_VETH" "${CLIENT_HOST_VETH[@]}"; do
    ip link show dev "$link" >/dev/null 2>&1 \
      && fail "network link already exists: $link"
  done
  return 0
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

issue_qkey() {
  printf '{"cmd":"qkey"}\n' | nc -U "$ADMIN_SOCKET" | python3 -c \
    'import json,sys; response=json.load(sys.stdin); assert response["success"]; print(response["data"]["qkey"])'
}

start_stack() {
  local phase="$1"
  local fec_mode="$2"
  shift 2
  local algorithms=("$@")
  stop_stack
  [[ ! -e "$ADMIN_SOCKET" ]] || fail "admin socket appeared before stack start: $ADMIN_SOCKET"
  ADMIN_SOCKET_OWNED=1

  local config="$ARTIFACT_DIR/config-$phase.toml"
  printf '[transport]\nmtu = 1280\nmax_udp_payload = 1280\ndisable_pmtud = false\npmtu_min_mtu = 1280\npmtu_max_mtu = 1280\n' \
    >"$config"
  ip netns exec "$SERVER_NS" "$BINARY" server \
    --config "$config" \
    --fec-mode "$fec_mode" \
    --cc-algorithm cubic \
    --cert "$CERT" \
    --key "$KEY" \
    --listen "$SERVER_UNDERLAY:4433" \
    --metrics-port "$METRICS_PORT" \
    --admin-socket "$ADMIN_SOCKET" \
    --tun \
    --tun-name "$TUN_NAME" \
    --tun-mtu 1280 \
    --tun-ip 10.0.1.1 \
    --tun-netmask 255.255.255.0 \
    --no-drop-privileges \
    -v >"$ARTIFACT_DIR/server-$phase.log" 2>&1 &
  STACK_PIDS+=("$!")
  wait_for_socket
  wait_for_metrics

  local index qkey log_file
  for index in "${!algorithms[@]}"; do
    qkey="$(issue_qkey)"
    log_file="$ARTIFACT_DIR/client-$phase-$((index + 1)).log"
    ip netns exec "${CLIENT_NS[$index]}" "$BINARY" client \
      --config "$config" \
      --fec-mode "$fec_mode" \
      --cc-algorithm "${algorithms[$index]}" \
      --remote "$SERVER_UNDERLAY:4433" \
      --url "https://$SERVER_UNDERLAY/" \
      --qkey "$qkey" \
      --ca-file "$CA" \
      --verify-peer \
      --disable-doh \
      --tun \
      --tun-name "$TUN_NAME" \
      --tun-mtu 1280 \
      --tun-ip "${CLIENT_TUN_IP[$index]}" \
      --tun-netmask 255.255.255.0 \
      --no-utls \
      -v >"$log_file" 2>&1 &
    STACK_PIDS+=("$!")
    wait_for_log_count "$log_file" 'TLS handshake complete' 1
  done
  wait_for_log_count "$ARTIFACT_DIR/server-$phase.log" 'New client connected:' "${#algorithms[@]}"
  configure_tuns "${#algorithms[@]}"
  capture_process_commands "$phase"
}

configure_tuns() {
  local client_count="$1"
  wait_for_tun "$SERVER_NS"
  ip netns exec "$SERVER_NS" ip link set "$TUN_NAME" mtu 1280 up
  local index
  for ((index = 0; index < client_count; index++)); do
    wait_for_tun "${CLIENT_NS[$index]}"
    ip netns exec "${CLIENT_NS[$index]}" ip link set "$TUN_NAME" mtu 1280 up
    local ready=0
    for ((attempt = 0; attempt < 20; attempt++)); do
      if ip netns exec "${CLIENT_NS[$index]}" ping -c 1 -W 1 \
        -I "${CLIENT_TUN_IP[$index]}" 10.0.1.1 >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 0.2
    done
    ((ready == 1)) || fail "client $((index + 1)) tunnel did not become ready"
  done
}

capture_process_commands() {
  local phase="$1"
  local pid
  : >"$ARTIFACT_DIR/processes-$phase.txt"
  for pid in "${STACK_PIDS[@]}"; do
    tr '\0' ' ' <"/proc/$pid/cmdline" >>"$ARTIFACT_DIR/processes-$phase.txt"
    printf '\n' >>"$ARTIFACT_DIR/processes-$phase.txt"
  done
}

start_performance_sampler() {
  local label="$1"
  [[ -z "$PERFORMANCE_SAMPLER_PID" ]] || fail 'performance sampler already active'
  PERFORMANCE_SAMPLER_OUTPUT="$ARTIFACT_DIR/performance-$label.json"
  [[ ! -e "$PERFORMANCE_SAMPLER_OUTPUT" ]] \
    || fail "refusing to replace performance artifact: $PERFORMANCE_SAMPLER_OUTPUT"
  local sampler_args=(
    "$PERFORMANCE_SAMPLER"
    --metrics-port "$METRICS_PORT"
    --output "$PERFORMANCE_SAMPLER_OUTPUT"
  )
  local pid
  for pid in "${STACK_PIDS[@]}"; do
    sampler_args+=(--pid "$pid")
  done
  ip netns exec "$SERVER_NS" python3 "${sampler_args[@]}" &
  PERFORMANCE_SAMPLER_PID="$!"
  sleep 0.5
  kill -0 "$PERFORMANCE_SAMPLER_PID" 2>/dev/null \
    || fail "performance sampler exited before $label workload"
}

stop_performance_sampler() {
  local label="$1"
  [[ -n "$PERFORMANCE_SAMPLER_PID" ]] || fail "performance sampler was not active for $label"
  kill -TERM "$PERFORMANCE_SAMPLER_PID" \
    || fail "could not stop performance sampler for $label"
  wait "$PERFORMANCE_SAMPLER_PID" \
    || fail "performance sampler failed for $label"
  PERFORMANCE_SAMPLER_PID=""
  [[ -s "$PERFORMANCE_SAMPLER_OUTPUT" ]] \
    || fail "performance sampler produced no artifact for $label"
  PERFORMANCE_SAMPLER_OUTPUT=""
}

capture_latency() {
  local label="$1"
  local output="$ARTIFACT_DIR/latency-$label.json"
  local raw="$ARTIFACT_DIR/latency-$label.txt"
  ip netns exec "${CLIENT_NS[0]}" ping -n -c 40 -i 0.1 -W 1 \
    -I "${CLIENT_TUN_IP[0]}" 10.0.1.1 >"$raw" || true
  python3 -c \
    'import json,pathlib,re,statistics,sys; values=[float(value) for value in re.findall(r"time[=<]([0-9.]+) ms",pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))]; minimum=int(sys.argv[3]); assert minimum<=len(values)<=40,len(values); ordered=sorted(values); percentile=lambda fraction: ordered[max(0,min(len(ordered)-1,int(len(ordered)*fraction+0.999999)-1))]; result={"samples":len(values),"packet_loss_percent":(40-len(values))/40*100.0,"p50_ms":statistics.median(values),"p95_ms":percentile(0.95),"maximum_ms":max(values)}; pathlib.Path(sys.argv[2]).write_text(json.dumps(result,sort_keys=True)+"\n",encoding="utf-8")' \
    "$raw" "$output" "$([[ "$label" == *-loss ]] && printf 30 || printf 40)" \
    || fail "could not parse $label latency samples"
}

validate_performance_phase() {
  local fec_mode="$1"
  local phase="$2"
  local label="$fec_mode-$phase"
  local latency_limit="$MAX_CLEAN_P95_LATENCY_MS"
  if [[ "$phase" == "loss" ]]; then
    latency_limit="$MAX_IMPAIRED_P95_LATENCY_MS"
  fi
  python3 -c \
    'import json,pathlib,sys; performance=json.load(open(sys.argv[1],encoding="utf-8")); latency=json.load(open(sys.argv[2],encoding="utf-8")); cpu_limit=float(sys.argv[4]); rss_limit=int(sys.argv[5]); fallback_limit=int(sys.argv[6]); latency_limit=float(sys.argv[7]); assert performance["cpu_one_core_percent"]<=cpu_limit,performance; assert performance["peak_process_rss_bytes"]<=rss_limit,performance; assert performance["allocation_deltas"]["grow"]+performance["allocation_deltas"]["ephemeral"]<=fallback_limit,performance; assert performance["peak_pending_packets"]<=256,performance; assert performance["peak_pending_bytes"]<=393216,performance; assert performance["rate_limited_delta"]==0,performance; assert latency["p95_ms"]<=latency_limit,latency; summary={"fec_mode":sys.argv[3],"phase":sys.argv[8],"limits":{"cpu_one_core_percent":cpu_limit,"peak_process_rss_bytes":rss_limit,"fallback_allocations":fallback_limit,"p95_latency_ms":latency_limit},"performance":performance,"latency":latency}; pathlib.Path(sys.argv[9]).write_text(json.dumps(summary,sort_keys=True)+"\n",encoding="utf-8")' \
    "$ARTIFACT_DIR/performance-$label.json" \
    "$ARTIFACT_DIR/latency-$label.json" \
    "$fec_mode" "$MAX_CPU_ONE_CORE_PERCENT" "$MAX_PEAK_RSS_BYTES" \
    "$MAX_FALLBACK_ALLOCATIONS" "$latency_limit" "$phase" \
    "$ARTIFACT_DIR/performance-summary-$label.json" \
    || fail "$label exceeded its runtime performance contract"
}

set_shared_bottleneck() {
  local rate="$1"
  local loss="${2:-}"
  tc qdisc del dev "$SERVER_HOST_VETH" root 2>/dev/null || true
  local netem=(netem delay 20ms limit 1000)
  if [[ -n "$loss" ]]; then
    netem+=(loss random "$loss")
  fi
  tc qdisc add dev "$SERVER_HOST_VETH" root handle 1: "${netem[@]}"
  tc qdisc add dev "$SERVER_HOST_VETH" parent 1: handle 2: \
    tbf rate "$rate" burst 64kb latency 200ms
}

start_udp_receiver() {
  local port="$1"
  local active_seconds="$2"
  local measured_seconds="$3"
  local output="$4"
  ip netns exec "$SERVER_NS" timeout "$((active_seconds + 5))" python3 -c '
import json
import socket
import sys
import time

port = int(sys.argv[1])
active_seconds = float(sys.argv[2])
measured_seconds = float(sys.argv[3])
output = sys.argv[4]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.0.1.1", port))
sock.settimeout(0.2)
deadline = time.monotonic() + active_seconds
sequences = set()
duplicates = 0
payload_size = 0
while time.monotonic() < deadline:
    try:
        payload, _ = sock.recvfrom(65535)
    except TimeoutError:
        continue
    if len(payload) < 8:
        continue
    sequence = int.from_bytes(payload[:8], "big")
    if sequence in sequences:
        duplicates += 1
        continue
    sequences.add(sequence)
    payload_size = max(payload_size, len(payload))
packets = len(sequences)
total_bytes = packets * payload_size
maximum_sequence = max(sequences, default=-1)
result = {
    "bits_per_second": total_bytes * 8.0 / measured_seconds,
    "bytes": total_bytes,
    "duplicates": duplicates,
    "missing_packets": maximum_sequence + 1 - packets,
    "packets": packets,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(result, handle, sort_keys=True)
' "$port" "$active_seconds" "$measured_seconds" "$output" &
  UDP_RECEIVER_PID="$!"
}

run_udp_sender() {
  local namespace="$1"
  local source_ip="$2"
  local port="$3"
  local rate_bps="$4"
  local duration="$5"
  local output="$6"
  ip netns exec "$namespace" timeout "$((duration + 5))" python3 -c '
import json
import socket
import sys
import time

source_ip = sys.argv[1]
port = int(sys.argv[2])
rate_bps = float(sys.argv[3])
duration = float(sys.argv[4])
output = sys.argv[5]
payload_size = 1100
interval = payload_size * 8.0 / rate_bps
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((source_ip, 0))
destination = ("10.0.1.1", port)
started = time.monotonic()
deadline = started + duration
next_send = started
sequence = 0
while time.monotonic() < deadline:
    payload = sequence.to_bytes(8, "big") + bytes(payload_size - 8)
    sock.sendto(payload, destination)
    sequence += 1
    next_send += interval
    delay = next_send - time.monotonic()
    if delay > 0:
        time.sleep(delay)
result = {"bytes": sequence * payload_size, "packets": sequence}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(result, handle, sort_keys=True)
' "$source_ip" "$port" "$rate_bps" "$duration" "$output"
}

run_fairness() {
  set_shared_bottleneck 2mbit
  local receiver_one receiver_two sender_one sender_two
  start_udp_receiver 55351 12 10 "$ARTIFACT_DIR/udp-receiver-fairness-cubic.json"
  receiver_one="$UDP_RECEIVER_PID"
  start_udp_receiver 55352 12 10 "$ARTIFACT_DIR/udp-receiver-fairness-reno.json"
  receiver_two="$UDP_RECEIVER_PID"
  sleep 0.5
  run_udp_sender "${CLIENT_NS[0]}" "${CLIENT_TUN_IP[0]}" 55351 4000000 10 \
    "$ARTIFACT_DIR/udp-sender-fairness-cubic.json" &
  sender_one="$!"
  run_udp_sender "${CLIENT_NS[1]}" "${CLIENT_TUN_IP[1]}" 55352 4000000 10 \
    "$ARTIFACT_DIR/udp-sender-fairness-reno.json" &
  sender_two="$!"
  wait "$sender_one" || fail 'CUBIC fairness sender failed'
  wait "$sender_two" || fail 'Reno fairness sender failed'
  wait "$receiver_one" || fail 'CUBIC fairness receiver failed'
  wait "$receiver_two" || fail 'Reno fairness receiver failed'
  tc -s qdisc show dev "$SERVER_HOST_VETH" >"$ARTIFACT_DIR/qdisc-fairness.txt"

  python3 -c \
    'import json,pathlib,sys; results=[json.load(open(path,encoding="utf-8")) for path in sys.argv[2:]]; values=[result["bits_per_second"] for result in results]; total=sum(values); jain=total**2/(2*sum(value**2 for value in values)); assert min(values)>0.05*total, values; assert jain>0.8, jain; assert all(result["duplicates"]==0 for result in results), results; summary=f"CUBIC/Reno fairness: cubic={values[0]/1e6:.3f} Mbit/s, reno={values[1]/1e6:.3f} Mbit/s, Jain={jain:.6f}"; pathlib.Path(sys.argv[1]).write_text(summary+"\n",encoding="utf-8"); print(summary)' \
    "$ARTIFACT_DIR/fairness-summary.txt" \
    "$ARTIFACT_DIR/udp-receiver-fairness-cubic.json" \
    "$ARTIFACT_DIR/udp-receiver-fairness-reno.json" || fail 'Jain fairness did not exceed 0.8'
}

run_loss_trial() {
  local fec_mode="$1"
  local phase="$2"
  local trial="$3"
  local port=$((55400 + trial))
  local server_pid
  if [[ "$phase" == "loss" ]]; then
    port=$((port + 10))
  fi
  start_udp_receiver "$port" 10 8 "$ARTIFACT_DIR/udp-receiver-$fec_mode-$phase-$trial.json"
  server_pid="$UDP_RECEIVER_PID"
  sleep 0.3
  run_udp_sender "${CLIENT_NS[0]}" "${CLIENT_TUN_IP[0]}" "$port" 3000000 8 \
    "$ARTIFACT_DIR/udp-sender-$fec_mode-$phase-$trial.json" || fail "$fec_mode $phase trial $trial sender failed"
  wait "$server_pid" || fail "$fec_mode $phase trial $trial receiver failed"
}

run_loss_comparison() {
  local fec_mode="$1"
  local phase trial
  local receiver_files=()
  for phase in baseline loss; do
    if [[ "$phase" == "baseline" ]]; then
      set_shared_bottleneck 5mbit
    else
      set_shared_bottleneck 5mbit "${LOSS_RATE_PERCENT}%"
    fi
    capture_latency "$fec_mode-$phase"
    start_performance_sampler "$fec_mode-$phase"
    for ((trial = 1; trial <= LOSS_TRIALS; trial++)); do
      run_loss_trial "$fec_mode" "$phase" "$trial"
      receiver_files+=("$ARTIFACT_DIR/udp-receiver-$fec_mode-$phase-$trial.json")
    done
    stop_performance_sampler "$fec_mode-$phase"
    validate_performance_phase "$fec_mode" "$phase"
    tc -s qdisc show dev "$SERVER_HOST_VETH" >"$ARTIFACT_DIR/qdisc-$fec_mode-$phase.txt"
  done
  grep -q "loss ${LOSS_RATE_PERCENT}%" "$ARTIFACT_DIR/qdisc-$fec_mode-loss.txt" \
    || fail "$fec_mode loss run did not activate ${LOSS_RATE_PERCENT}% netem loss"

  python3 -c \
    'import json,pathlib,statistics,sys; summary_path=pathlib.Path(sys.argv[1]); fec_mode=sys.argv[2]; minimum=float(sys.argv[3]); trial_count=int(sys.argv[4]); results=[json.load(open(path,encoding="utf-8")) for path in sys.argv[5:]]; assert len(results)==2*trial_count, len(results); values=[result["bits_per_second"] for result in results]; groups=[values[:trial_count],values[trial_count:]]; assert all(value>0 for value in values), values; assert all(result["duplicates"]==0 for result in results), results; baseline=statistics.median(groups[0]); loss=statistics.median(groups[1]); ratio=loss/baseline; assert ratio>minimum, ratio; summary={"fec_mode":fec_mode,"trial_count":trial_count,"baseline_bits_per_second":baseline,"loss_bits_per_second":loss,"retained_ratio":ratio,"minimum_retained_ratio":minimum}; summary_path.write_text(json.dumps(summary,sort_keys=True)+"\n",encoding="utf-8"); print(f"CUBIC FEC {fec_mode}: baseline={baseline/1e6:.3f} Mbit/s, loss={loss/1e6:.3f} Mbit/s, retained={ratio*100:.2f}%")' \
    "$ARTIFACT_DIR/loss-summary-$fec_mode.json" \
    "$fec_mode" "$MIN_RETAINED_RATIO" "$LOSS_TRIALS" \
    "${receiver_files[@]}" || \
    fail "CUBIC FEC $fec_mode random-loss throughput did not retain more than $MIN_RETAINED_PERCENT% of baseline"
}

compare_fec_modes() {
  python3 -c \
    'import json,pathlib,sys; auto=json.load(open(sys.argv[2],encoding="utf-8")); off=json.load(open(sys.argv[3],encoding="utf-8")); assert auto["fec_mode"]=="auto", auto; assert off["fec_mode"]=="off", off; comparison={"auto":auto,"off":off,"auto_minus_off_loss_bits_per_second":auto["loss_bits_per_second"]-off["loss_bits_per_second"],"auto_minus_off_retained_percentage_points":(auto["retained_ratio"]-off["retained_ratio"])*100.0}; pathlib.Path(sys.argv[1]).write_text(json.dumps(comparison,sort_keys=True)+"\n",encoding="utf-8"); print("CUBIC FEC comparison: auto loss={auto_loss:.3f} Mbit/s, retained={auto_retained:.2f}%; off loss={off_loss:.3f} Mbit/s, retained={off_retained:.2f}%; auto-minus-off loss={delta_loss:.3f} Mbit/s, retained={delta_retained:.2f} pp".format(auto_loss=auto["loss_bits_per_second"]/1e6,auto_retained=auto["retained_ratio"]*100.0,off_loss=off["loss_bits_per_second"]/1e6,off_retained=off["retained_ratio"]*100.0,delta_loss=comparison["auto_minus_off_loss_bits_per_second"]/1e6,delta_retained=comparison["auto_minus_off_retained_percentage_points"]))' \
    "$ARTIFACT_DIR/fec-comparison-summary.json" \
    "$ARTIFACT_DIR/loss-summary-auto.json" \
    "$ARTIFACT_DIR/loss-summary-off.json" || \
    fail 'CUBIC FEC control comparison could not be recorded'
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || fail 'this proof requires Linux network namespaces'
  [[ "${EUID:-$(id -u)}" == "0" ]] || fail 'this proof requires root'
  local command
  for command in flock ip nc openssl ping python3 sha256sum sysctl tc timeout; do
    require_command "$command"
  done
  [[ -x "$BINARY" ]] || fail "release binary not executable: $BINARY"
  [[ -r "$PERFORMANCE_SAMPLER" ]] \
    || fail "performance sampler is unreadable: $PERFORMANCE_SAMPLER"
  [[ -r "$CA" && -r "$CA_KEY" ]] || fail 'CA certificate or key fixture is unreadable'

  exec 9>"$LOCK_FILE"
  flock -w "$LOCK_TIMEOUT" 9 || fail "could not acquire E2E lock within ${LOCK_TIMEOUT}s"
  preflight_owned_resources
  prepare_admin_socket
  setup_topology

  log 'phase 1: CUBIC/Reno shared-bottleneck fairness'
  start_stack fairness off cubic reno
  run_fairness
  stop_stack

  local fec_mode
  for fec_mode in auto off; do
    log "phase 2: CUBIC $fec_mode clean baseline versus controlled ${LOSS_RATE_PERCENT}% random loss"
    start_stack "loss-$fec_mode" "$fec_mode" cubic
    run_loss_comparison "$fec_mode"
    stop_stack
  done
  compare_fec_modes
  prove_runtime_logs_clean

  cat "$ARTIFACT_DIR/fairness-summary.txt"
  cat "$ARTIFACT_DIR/loss-summary-auto.json"
  cat "$ARTIFACT_DIR/loss-summary-off.json"
  cat "$ARTIFACT_DIR/fec-comparison-summary.json"
  log "PASS: complete evidence retained in $ARTIFACT_DIR"
}

main "$@"
