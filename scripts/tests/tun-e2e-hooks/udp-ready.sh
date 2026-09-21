#!/usr/bin/env bash
# UDP evidence hook for tun-e2e-netns.sh (TODO-1025).
#
# Contract (env):
#   TAG            run label, default udp
#   UDPRATE        iperf3 UDP offered rate, default 60M
#   DURATION       iperf3 seconds, default 15
#   QF_E2E_HOOK_OUTPUT_DIR  optional absolute evidence directory
#
# Runs inside the already-prepared ns-srv/ns-cli namespaces, dumps qtun0
# counters, drives iperf3 UDP, and writes counters + receiver loss to
# stdout (e2e run log) and a named evidence file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ready-lib.sh
. "$SCRIPT_DIR/ready-lib.sh"

require_cmd ip
require_cmd iperf3
require_cmd timeout

TAG="${TAG:-udp}"
UDPRATE="${UDPRATE:-60M}"
DURATION="${DURATION:-15}"
IPERF_LEN="${IPERF_LEN:-}"
prepare_evidence_dir "$TAG"

SERVER_LOG="$EVIDENCE_DIR/${TAG}.iperf-server.log"
CLIENT_JSON="$EVIDENCE_DIR/${TAG}.iperf-client.json"
for path in "$SERVER_LOG" "$CLIENT_JSON"; do
  [ ! -e "$path" ] || fail "refusing to overwrite evidence path: $path"
done

emit "schema=quicfuscate.tun-e2e-udp-ready.v1"
emit "tag=${TAG}"
emit "udprate=${UDPRATE}"
emit "duration=${DURATION}"
emit "iperf_len=${IPERF_LEN:-default}"
emit "project_root=${PROJECT_ROOT}"

qtun_counters ns-srv | tee -a "$EVIDENCE_FILE"
qtun_counters ns-cli | tee -a "$EVIDENCE_FILE"
emit "qtun0_tx_dropped_cli_before=$(qtun_tx_dropped ns-cli)"
emit "qtun0_tx_dropped_srv_before=$(qtun_tx_dropped ns-srv)"

ip netns exec ns-srv iperf3 -s -B 10.0.1.1 -p 5201 --one-off >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap 'stop_pid "$SERVER_PID"' EXIT
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || fail "iperf3 server did not stay up"

IPERF_ARGS=(-c 10.0.1.1 -B 10.0.1.2 -p 5201 -u -b "$UDPRATE" -t "$DURATION" -J)
if [ -n "$IPERF_LEN" ]; then
  IPERF_ARGS+=(-l "$IPERF_LEN")
fi
if ! ip netns exec ns-cli timeout $((DURATION + 5)) iperf3 "${IPERF_ARGS[@]}" >"$CLIENT_JSON"; then
  fail "iperf3 UDP client did not terminate successfully"
fi
stop_pid "$SERVER_PID"
SERVER_PID=""
trap - EXIT

qtun_counters ns-srv | tee -a "$EVIDENCE_FILE"
qtun_counters ns-cli | tee -a "$EVIDENCE_FILE"
emit "qtun0_tx_dropped_cli_after=$(qtun_tx_dropped ns-cli)"
emit "qtun0_tx_dropped_srv_after=$(qtun_tx_dropped ns-srv)"

python3 - "$CLIENT_JSON" "$EVIDENCE_FILE" <<'PY'
import json, sys
path, evidence = sys.argv[1], sys.argv[2]
data = json.loads(open(path, encoding="utf-8").read())
end = data.get("end") or {}
sum_recv = end.get("sum") or end.get("sum_received") or {}
lost = int(sum_recv.get("lost_packets") or 0)
total = int(sum_recv.get("packets") or 0)
bps = float(sum_recv.get("bits_per_second") or 0.0)
lost_percent = float(sum_recv.get("lost_percent") or 0.0)
lines = [
    f"iperf_lost={lost}",
    f"iperf_packets={total}",
    f"iperf_lost_percent={lost_percent}",
    f"iperf_recv_mbits={bps / 1_000_000:.3f}",
]
text = "\n".join(lines) + "\n"
sys.stdout.write(text)
with open(evidence, "a", encoding="utf-8") as handle:
    handle.write(text)
if total <= 0:
    raise SystemExit("iperf3 UDP receiver reported no packets")
PY

if [ -f /tmp/ns-cli.log ]; then
  emit "=== client stats ==="
  grep -E "client stats:|FEC|wire|streaming|yield_window|reorder_window" /tmp/ns-cli.log | tail -24 | tee -a "$EVIDENCE_FILE"
fi
if [ -f /tmp/ns-srv-restart.log ]; then
  emit "=== server fec ==="
  grep -iE "fec|streaming|wire profile" /tmp/ns-srv-restart.log | tail -10 | tee -a "$EVIDENCE_FILE" || true
fi

emit "evidence_file=${EVIDENCE_FILE}"
echo "PASS: UDP ready hook ${TAG} wrote ${EVIDENCE_FILE}"
