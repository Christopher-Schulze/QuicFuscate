#!/usr/bin/env bash
# Run packet capture and classifier probes while tun-e2e-netns.sh owns the
# authenticated namespaces and product processes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_PCAP="$SCRIPT_DIR/utils/verify-fingerprint-pcap.py"
OUTPUT_DIR="${QF_E2E_HOOK_OUTPUT_DIR:-}"
PROFILE="${QF_E2E_HOOK_PROFILE:-}"
P0F_PID=""
CLIENT_CAPTURE_PID=""
SERVER_CAPTURE_PID=""
SERVER_LISTENER_PID=""
CLIENT_LISTENER_PID=""

fail() {
  echo "FAIL: fingerprint runtime hook: $*" >&2
  exit 1
}

stop_process() {
  local pid="$1"
  if [ -z "$pid" ]; then
    return
  fi
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  stop_process "$CLIENT_LISTENER_PID"
  CLIENT_LISTENER_PID=""
  stop_process "$SERVER_LISTENER_PID"
  SERVER_LISTENER_PID=""
  stop_process "$P0F_PID"
  P0F_PID=""
  stop_process "$CLIENT_CAPTURE_PID"
  CLIENT_CAPTURE_PID=""
  stop_process "$SERVER_CAPTURE_PID"
  SERVER_CAPTURE_PID=""
}
trap cleanup EXIT

if [ -z "$OUTPUT_DIR" ] || [ "${OUTPUT_DIR#/}" = "$OUTPUT_DIR" ]; then
  fail "QF_E2E_HOOK_OUTPUT_DIR must be an absolute path"
fi
if [[ ! "$PROFILE" =~ ^(disabled|linux|windows|macos|android)$ ]]; then
  fail "unsupported fingerprint profile: $PROFILE"
fi
if [ ! -x "$VERIFY_PCAP" ]; then
  fail "pcap verifier is not executable: $VERIFY_PCAP"
fi
if [ ! -d "$OUTPUT_DIR" ]; then
  fail "hook output directory does not exist: $OUTPUT_DIR"
fi

CLIENT_PCAP="$OUTPUT_DIR/client.pcap"
SERVER_PCAP="$OUTPUT_DIR/server.pcap"
P0F_LOG="$OUTPUT_DIR/p0f.log"
P0F_STDERR="$OUTPUT_DIR/p0f.stderr.log"
NMAP_LOG="$OUTPUT_DIR/nmap.log"
NMAP_STATUS="$OUTPUT_DIR/nmap.status"
PING_LOG="$OUTPUT_DIR/icmp-echo.log"
PROBE_MANIFEST="$OUTPUT_DIR/probe-manifest.txt"
for path in "$CLIENT_PCAP" "$SERVER_PCAP" "$P0F_LOG" "$P0F_STDERR" "$NMAP_LOG" "$NMAP_STATUS" "$PING_LOG" "$PROBE_MANIFEST"; do
  [ ! -e "$path" ] || fail "refusing to overwrite evidence path: $path"
done

printf '%s\n' \
  'schema=quicfuscate.fingerprint-active-probes.v1' \
  'icmp_echo=ping -c 1 -W 3 -I qtun0 10.0.1.2' \
  'nmap=nmap -O --osscan-guess -sS -sU -PE -Pn -n -p T:18080,18082,U:18081 --reason --packet-trace --max-retries 1 --host-timeout 30s 10.0.1.2' \
  'tcp_open_port=18080' \
  'tcp_closed_port=18082' \
  'udp_closed_port=18081' \
  'response_direction=10.0.1.2->10.0.1.1' > "$PROBE_MANIFEST"

ip netns exec ns-cli tcpdump --immediate-mode -U -n -s 0 -B 4096 -i qtun0 \
  -w "$CLIENT_PCAP" 'ip' >"$OUTPUT_DIR/client-tcpdump.log" 2>&1 &
CLIENT_CAPTURE_PID=$!
ip netns exec ns-srv tcpdump --immediate-mode -U -n -s 0 -B 4096 -i qtun0 \
  -w "$SERVER_PCAP" 'ip' >"$OUTPUT_DIR/server-tcpdump.log" 2>&1 &
SERVER_CAPTURE_PID=$!
sleep 1
kill -0 "$CLIENT_CAPTURE_PID" 2>/dev/null || fail "client tcpdump did not remain active"
kill -0 "$SERVER_CAPTURE_PID" 2>/dev/null || fail "server tcpdump did not remain active"

ip netns exec ns-srv p0f -i qtun0 -o "$P0F_LOG" >"$P0F_STDERR" 2>&1 &
P0F_PID=$!
sleep 1
kill -0 "$P0F_PID" 2>/dev/null || fail "p0f did not remain active"

SERVER_LISTENER_CODE='import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.0.1.1",18081)); s.listen(1); s.settimeout(20); c,_=s.accept(); c.close(); s.close()'
ip netns exec ns-srv timeout 25s python3 -c "$SERVER_LISTENER_CODE" \
  >"$OUTPUT_DIR/server-listener.log" 2>&1 &
SERVER_LISTENER_PID=$!
sleep 1
ip netns exec ns-cli python3 -c \
  'import socket; s=socket.create_connection(("10.0.1.1",18081),5); s.close()' \
  >"$OUTPUT_DIR/client-syn.log" 2>&1 || fail "client SYN probe failed"

CLIENT_LISTENER_CODE='import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.0.1.2",18080)); s.listen(8); s.settimeout(10); c,_=s.accept(); c.close(); time.sleep(25); s.close()'
ip netns exec ns-cli timeout 40s python3 -c "$CLIENT_LISTENER_CODE" \
  >"$OUTPUT_DIR/client-listener.log" 2>&1 &
CLIENT_LISTENER_PID=$!
sleep 1
ip netns exec ns-srv ping -c 1 -W 3 -I qtun0 10.0.1.2 >"$PING_LOG" 2>&1 \
  || fail "client ICMP echo probe failed"
set +e
ip netns exec ns-srv nmap -O --osscan-guess -sS -sU -PE -Pn -n \
  -p 'T:18080,18082,U:18081' --reason --packet-trace --max-retries 1 \
  --host-timeout 30s 10.0.1.2 >"$NMAP_LOG" 2>&1
NMAP_EXIT=$?
set -e
printf '%s\n' "$NMAP_EXIT" > "$NMAP_STATUS"
[ "$NMAP_EXIT" -eq 0 ] || fail "active Nmap probe matrix failed with exit $NMAP_EXIT"

sleep 1
stop_process "$CLIENT_LISTENER_PID"
CLIENT_LISTENER_PID=""
stop_process "$SERVER_LISTENER_PID"
SERVER_LISTENER_PID=""
stop_process "$P0F_PID"
P0F_PID=""
stop_process "$CLIENT_CAPTURE_PID"
CLIENT_CAPTURE_PID=""
stop_process "$SERVER_CAPTURE_PID"
SERVER_CAPTURE_PID=""

[ -s "$CLIENT_PCAP" ] || fail "client capture is empty"
[ -s "$SERVER_PCAP" ] || fail "server capture is empty"
python3 "$VERIFY_PCAP" --profile "$PROFILE" --client-pcap "$CLIENT_PCAP" \
  --server-pcap "$SERVER_PCAP" --nmap-log "$NMAP_LOG" \
  --output "$OUTPUT_DIR/packet-verification.json"

printf 'schema=quicfuscate.fingerprint-runtime-hook.v1\nprofile=%s\nnmap_exit=%s\n' \
  "$PROFILE" "$NMAP_EXIT" > "$OUTPUT_DIR/hook-summary.txt"
