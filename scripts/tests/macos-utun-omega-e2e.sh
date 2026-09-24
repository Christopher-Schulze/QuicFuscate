#!/usr/bin/env bash
# Native macOS-to-Linux authenticated CONNECT-IP proof against the Omega E2E
# endpoint. Mirrors the Windows wintun-omega-e2e.ps1 gate:
#   authenticated client -> kernel utun opens from server assignment ->
#   IPv4 + IPv6 echo through the tunnel -> graceful shutdown -> zero utun,
#   route, and pf-anchor residue.
#
# Required environment:
#   QF_MACOS_E2E_QKEY      QKey minted on the Omega E2E admin socket
#   QF_MACOS_E2E_CA        path to the Omega E2E CA certificate (PEM)
# Optional:
#   QF_MACOS_E2E_ENDPOINT  default 92.5.237.185:4433
#   QF_MACOS_E2E_BINARY    default target/debug/quicfuscate
#   QF_MACOS_E2E_TIMEOUT   readiness wait seconds, default 60
set -euo pipefail

ENDPOINT="${QF_MACOS_E2E_ENDPOINT:-92.5.237.185:4433}"
ENDPOINT_HOST="${ENDPOINT%%:*}"
BINARY="${QF_MACOS_E2E_BINARY:-target/debug/quicfuscate}"
TIMEOUT="${QF_MACOS_E2E_TIMEOUT:-60}"
PF_ANCHOR="com.quicfuscate.killswitch"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "root is required (utun, routes, pf anchor)"
[ -n "${QF_MACOS_E2E_QKEY:-}" ] || fail "QF_MACOS_E2E_QKEY is not set"
[ -n "${QF_MACOS_E2E_CA:-}" ] || fail "QF_MACOS_E2E_CA is not set"
[ -f "$QF_MACOS_E2E_CA" ] || fail "CA file missing: $QF_MACOS_E2E_CA"
[ -x "$BINARY" ] || fail "client binary missing: $BINARY (run: cargo build --bin quicfuscate)"

WORK_DIR="$(mktemp -d /tmp/qf-macos-e2e.XXXXXX)"
CLIENT_PID=""

cleanup() {
  [ -n "$CLIENT_PID" ] && kill -TERM "$CLIENT_PID" 2>/dev/null || true
  [ -n "$CLIENT_PID" ] && wait "$CLIENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

BASELINE_UTUNS="$(ifconfig -l | tr ' ' '\n' | grep -c '^utun' || true)"

QUICFUSCATE_MASQUE_TRACE=1 "$BINARY" client \
  --remote "$ENDPOINT" \
  --url "https://$ENDPOINT_HOST/" \
  --qkey "$QF_MACOS_E2E_QKEY" \
  --ca-file "$QF_MACOS_E2E_CA" \
  --verify-peer \
  --no-utls \
  --disable-doh \
  --tun \
  --tun-name utun \
  --kill-switch \
  --heartbeat-timeout-ms 15000 \
  -v > "$WORK_DIR/client.log" 2>&1 &
CLIENT_PID=$!

ready=""
for ((attempt = 0; attempt < TIMEOUT; attempt++)); do
  if grep -q 'TUN interface opened from server assignment' "$WORK_DIR/client.log" 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$CLIENT_PID" 2>/dev/null || break
  sleep 1
done
[ -n "$ready" ] || { tail -30 "$WORK_DIR/client.log" >&2; fail "client did not reach TUN assignment"; }

UTUN_IF=""
for ((attempt = 0; attempt < 10; attempt++)); do
  UTUN_IF="$(ifconfig -l | tr ' ' '\n' | grep '^utun' | while read -r i; do
    ifconfig "$i" 2>/dev/null | grep -q 'inet 10\.252\.0\.' && echo "$i"
  done | head -1)"
  [ -n "$UTUN_IF" ] && break
  sleep 1
done
[ -n "$UTUN_IF" ] || { tail -30 "$WORK_DIR/client.log" >&2; fail "no utun with a 10.252.0.x address appeared"; }
echo "INFO: tunnel interface up: $UTUN_IF"

ping -c 5 -t 10 10.252.0.1 > "$WORK_DIR/ping4.log" 2>&1 \
  || fail "IPv4 tunnel ping failed: $(tail -3 "$WORK_DIR/ping4.log")"
ping6 -c 5 fd00::1 > "$WORK_DIR/ping6.log" 2>&1 \
  || fail "IPv6 tunnel ping failed: $(tail -3 "$WORK_DIR/ping6.log")"
echo "INFO: IPv4/IPv6 tunnel pings passed"

kill -TERM "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

sleep 2
if ifconfig -l | tr ' ' '\n' | grep -q "^$UTUN_IF$"; then
  fail "utun residue remains after graceful shutdown: $UTUN_IF"
fi
CURRENT_UTUNS="$(ifconfig -l | tr ' ' '\n' | grep -c '^utun' || true)"
[ "$CURRENT_UTUNS" = "$BASELINE_UTUNS" ] \
  || fail "utun count drifted: baseline=$BASELINE_UTUNS now=$CURRENT_UTUNS"
if pfctl -sA 2>/dev/null | grep -q "$PF_ANCHOR"; then
  fail "pf anchor residue remains after graceful shutdown: $PF_ANCHOR"
fi
if netstat -nr -f inet 2>/dev/null | grep -q "$UTUN_IF"; then
  fail "route residue remains after graceful shutdown on $UTUN_IF"
fi

echo "PASS: authenticated macOS utun tunnel carried bidirectional IPv4/IPv6 ICMP against the Omega exit and left zero utun/route/pf residue"
