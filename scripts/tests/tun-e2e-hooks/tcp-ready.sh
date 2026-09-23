#!/usr/bin/env bash
# TCP evidence hook for tun-e2e-netns.sh (TODO-1025).
#
# Contract (env):
#   TAG            run label, default tcp
#   DURATION       iperf3 seconds, default 15
#   QF_E2E_HOOK_OUTPUT_DIR  optional absolute evidence directory
#   QF_E2E_LOG_DIR         runner log directory, default /tmp (TODO-1071)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ready-lib.sh
. "$SCRIPT_DIR/ready-lib.sh"

require_cmd ip
require_cmd timeout
if [ -z "${IPERF_NC:-}" ]; then
  require_cmd iperf3
fi

TAG="${TAG:-tcp}"
DURATION="${DURATION:-15}"
IPERF_REVERSE="${IPERF_REVERSE:-}"
IPERF_MSS="${IPERF_MSS:-}"
IPERF_SWAP="${IPERF_SWAP:-}"
IPERF_NC="${IPERF_NC:-}"
E2E_LOG_DIR="${QF_E2E_LOG_DIR:-/tmp}"
prepare_evidence_dir "$TAG"

SERVER_LOG="$EVIDENCE_DIR/${TAG}.iperf-server.log"
CLIENT_JSON="$EVIDENCE_DIR/${TAG}.iperf-client.json"
NC_SINK="$EVIDENCE_DIR/${TAG}.nc-sink"
if [ -n "$IPERF_NC" ]; then
  [ ! -e "$NC_SINK" ] || fail "refusing to overwrite evidence path: $NC_SINK"
else
  for path in "$SERVER_LOG" "$CLIENT_JSON"; do
    [ ! -e "$path" ] || fail "refusing to overwrite evidence path: $path"
  done
fi

emit "schema=quicfuscate.tun-e2e-tcp-ready.v1"
emit "tag=${TAG}"
emit "duration=${DURATION}"
emit "iperf_reverse=${IPERF_REVERSE:-0}"
emit "iperf_swap=${IPERF_SWAP:-0}"
emit "iperf_nc=${IPERF_NC:-0}"
emit "iperf_mss=${IPERF_MSS:-default}"
emit "project_root=${PROJECT_ROOT}"

qtun_counters ns-srv | tee -a "$EVIDENCE_FILE"
qtun_counters ns-cli | tee -a "$EVIDENCE_FILE"
emit "qtun0_tx_dropped_cli_before=$(qtun_tx_dropped ns-cli)"
emit "qtun0_tx_dropped_srv_before=$(qtun_tx_dropped ns-srv)"

if [ -n "$IPERF_SWAP" ]; then
  LISTEN_NS=ns-cli
  LISTEN_BIND=10.0.1.2
  SEND_NS=ns-srv
  SEND_BIND=10.0.1.1
  SEND_TARGET=10.0.1.2
else
  LISTEN_NS=ns-srv
  LISTEN_BIND=10.0.1.1
  SEND_NS=ns-cli
  SEND_BIND=10.0.1.2
  SEND_TARGET=10.0.1.1
fi

CAPTURE_PID=""
if [ -n "${CAPTURE_SIZES:-}" ]; then
  require_cmd tcpdump
  CAPTURE_LOG="$EVIDENCE_DIR/${TAG}.qtun-sizes.txt"
  [ ! -e "$CAPTURE_LOG" ] || fail "refusing to overwrite evidence path: $CAPTURE_LOG"
  ip netns exec ns-srv timeout $((DURATION + 25)) tcpdump -nni qtun0 -c 4000 -q \
    >"$CAPTURE_LOG" 2>"$EVIDENCE_DIR/${TAG}.qtun-sizes.err" &
  CAPTURE_PID=$!
fi

SERVER_PID=""
if [ -n "$IPERF_NC" ]; then
  require_cmd nc
  require_cmd dd
  : >"$NC_SINK"
  ip netns exec "$LISTEN_NS" timeout $((DURATION + 8)) nc -l -s "$LISTEN_BIND" -p 9999 >"$NC_SINK" 2>"$EVIDENCE_DIR/${TAG}.nc-listen.err" &
  SERVER_PID=$!
  cleanup_ready() {
    stop_pid "$SERVER_PID"
    stop_pid "$CAPTURE_PID"
  }
  trap cleanup_ready EXIT
  sleep 1
  kill -0 "$SERVER_PID" 2>/dev/null || fail "nc listener did not stay up"
  if ! ip netns exec "$SEND_NS" timeout $((DURATION + 5)) \
    dd if=/dev/zero bs=1400 count=20000 status=none \
    | ip netns exec "$SEND_NS" timeout $((DURATION + 5)) nc -N -s "$SEND_BIND" "$SEND_TARGET" 9999
  then
    emit "nc_sender_nonzero_exit=1"
  fi
  stop_pid "$SERVER_PID"
  SERVER_PID=""
  NC_BYTES=$(wc -c <"$NC_SINK" | tr -d ' ')
  emit "nc_recv_bytes=${NC_BYTES}"
  emit "iperf_recv_bytes=${NC_BYTES}"
  emit "iperf_sent_bytes=${NC_BYTES}"
  python3 -c "print('iperf_recv_mbits=%.3f' % (${NC_BYTES:-0} * 8 / max(${DURATION}, 1) / 1e6))" | tee -a "$EVIDENCE_FILE"
  emit "iperf_retransmits=0"
else
  ip netns exec "$LISTEN_NS" iperf3 -s -B "$LISTEN_BIND" -p 5201 --one-off >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  cleanup_ready() {
    stop_pid "$SERVER_PID"
    stop_pid "$CAPTURE_PID"
  }
  trap cleanup_ready EXIT
  sleep 1
  kill -0 "$SERVER_PID" 2>/dev/null || fail "iperf3 server did not stay up"

  IPERF_ARGS=(-c "$SEND_TARGET" -B "$SEND_BIND" -p 5201 -t "$DURATION" -J)
  if [ -n "$IPERF_REVERSE" ]; then
    IPERF_ARGS+=(-R)
  fi
  if [ -n "$IPERF_MSS" ]; then
    IPERF_ARGS+=(-M "$IPERF_MSS")
  fi
  if ! ip netns exec "$SEND_NS" timeout $((DURATION + 20)) iperf3 "${IPERF_ARGS[@]}" >"$CLIENT_JSON"; then
    if [ ! -s "$CLIENT_JSON" ]; then
      fail "iperf3 TCP client did not terminate successfully"
    fi
    emit "iperf_client_nonzero_exit=1"
  fi
  stop_pid "$SERVER_PID"
  SERVER_PID=""
fi
if [ -n "$CAPTURE_PID" ]; then
  stop_pid "$CAPTURE_PID"
  CAPTURE_PID=""
  if [ -s "$EVIDENCE_DIR/${TAG}.qtun-sizes.txt" ]; then
    emit "=== qtun0 size histogram ==="
    python3 - "$EVIDENCE_DIR/${TAG}.qtun-sizes.txt" "$EVIDENCE_FILE" <<'PY'
import re, sys
from collections import Counter
path, evidence = sys.argv[1], sys.argv[2]
# tcpdump -q: "IP a.b > c.d: tcp 1373"
alt = re.compile(r"\btcp\s+(\d+)\b|\blength\s+(\d+)\b")
counts = Counter()
icmp = 0
other = 0
with open(path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        if "ICMP" in line or "icmp" in line:
            icmp += 1
            continue
        match = alt.search(line)
        if not match:
            other += 1
            continue
        size = int(match.group(1) or match.group(2))
        counts[size] += 1
lines = [f"capture_icmp={icmp}", f"capture_other={other}", f"capture_tcp_sizes={len(counts)}"]
for size, count in counts.most_common(16):
    lines.append(f"tcp_payload_{size}={count}")
text = "\n".join(lines) + "\n"
sys.stdout.write(text)
with open(evidence, "a", encoding="utf-8") as handle:
    handle.write(text)
PY
  fi
fi
trap - EXIT

qtun_counters ns-srv | tee -a "$EVIDENCE_FILE"
qtun_counters ns-cli | tee -a "$EVIDENCE_FILE"
emit "qtun0_tx_dropped_cli_after=$(qtun_tx_dropped ns-cli)"
emit "qtun0_tx_dropped_srv_after=$(qtun_tx_dropped ns-srv)"
emit "=== ss tun sockets ==="
ip netns exec ns-srv ss -ti dst 10.0.1.2 or src 10.0.1.1 2>/dev/null | tee -a "$EVIDENCE_FILE" || true
ip netns exec ns-cli ss -ti dst 10.0.1.1 or src 10.0.1.2 2>/dev/null | tee -a "$EVIDENCE_FILE" || true

if [ -n "$IPERF_NC" ]; then
  if [ "${NC_BYTES:-0}" = "0" ]; then
    fail "nc TCP reported no bytes"
  fi
else
python3 - "$CLIENT_JSON" "$EVIDENCE_FILE" <<'PY'
import json, sys
path, evidence = sys.argv[1], sys.argv[2]
data = json.loads(open(path, encoding="utf-8").read())
end = data.get("end") or {}
recv = end.get("sum_received") or {}
sent = end.get("sum_sent") or end.get("sum") or {}
recv_bytes = int(recv.get("bytes") or 0)
sent_bytes = int(sent.get("bytes") or 0)
bps = float(recv.get("bits_per_second") or 0.0)
if bps <= 0.0:
    bps = float(sent.get("bits_per_second") or 0.0)
retrans = int(sent.get("retransmits") or 0)
lines = [
    f"iperf_recv_bytes={recv_bytes}",
    f"iperf_sent_bytes={sent_bytes}",
    f"iperf_recv_mbits={bps / 1_000_000:.3f}",
    f"iperf_retransmits={retrans}",
]
text = "\n".join(lines) + "\n"
sys.stdout.write(text)
with open(evidence, "a", encoding="utf-8") as handle:
    handle.write(text)
if recv_bytes <= 0 and sent_bytes <= 0:
    raise SystemExit("iperf3 TCP reported no bytes")
PY
fi

if [ -f "$E2E_LOG_DIR/ns-cli.log" ]; then
  emit "=== client stats ==="
  grep -E "client stats:|FEC" "$E2E_LOG_DIR/ns-cli.log" | tail -8 | tee -a "$EVIDENCE_FILE"
fi

emit "evidence_file=${EVIDENCE_FILE}"
echo "PASS: TCP ready hook ${TAG} wrote ${EVIDENCE_FILE}"
