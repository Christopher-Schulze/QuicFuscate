#!/usr/bin/env bash
# Sequential Omega evidence batch. Replaces nothing; writes /tmp/qf-e2e-hooks.
# Requires a single checkout at PROJECT_ROOT and a release binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export PROJECT_ROOT
export QF_E2E_BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
export QF_E2E_HOOK_OUTPUT_DIR="${QF_E2E_HOOK_OUTPUT_DIR:-/tmp/qf-e2e-hooks}"
FEC_STREAMING="$SCRIPT_DIR/tun-e2e-hooks/fec-streaming.toml"
SUMMARY="$QF_E2E_HOOK_OUTPUT_DIR/batch-summary.txt"

if [ ! -x "$QF_E2E_BINARY" ]; then
  echo "FAIL: missing release binary: $QF_E2E_BINARY" >&2
  exit 2
fi

mkdir -p "$QF_E2E_HOOK_OUTPUT_DIR"
{
  echo "schema=quicfuscate.tun-e2e-omega-batch.v1"
  echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "binary=$QF_E2E_BINARY"
  echo "project_root=$PROJECT_ROOT"
} >"$SUMMARY"

run_step() {
  local name="$1"
  shift
  echo "=== STEP ${name} ==="
  echo "step_${name}_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$SUMMARY"
  if "$@"; then
    echo "step_${name}=PASS" >>"$SUMMARY"
  else
    echo "step_${name}=FAIL rc=$?" >>"$SUMMARY"
    echo "FAIL: step ${name}" >&2
    exit 1
  fi
}

# 0. ping-only sanity
run_step ping env -u QF_E2E_READY_HOOK -u QF_E2E_FEC_CONFIG \
  -u QUICFUSCATE_STEALTH_JITTER_US \
  "$SCRIPT_DIR/tun-e2e-netns.sh"

# 1. UDP 60M reorder off (TODO-1015/1016 baseline)
run_step udp60_off env TAG=udp60-off UDPRATE=60M DURATION=15 \
  QUICFUSCATE_STEALTH_JITTER_US=0 \
  "$SCRIPT_DIR/tun-e2e-omega-udp.sh"

# 2. UDP 60M reorder on
run_step udp60_on env TAG=udp60-on UDPRATE=60M DURATION=15 \
  QUICFUSCATE_STEALTH_JITTER_US=5000 \
  "$SCRIPT_DIR/tun-e2e-omega-udp.sh"

# 3. UDP 140M saturation with reorder
run_step udp140_on env TAG=udp140-on UDPRATE=140M DURATION=15 \
  QUICFUSCATE_STEALTH_JITTER_US=5000 \
  "$SCRIPT_DIR/tun-e2e-omega-udp.sh"

# 4. TODO-1022: Protected UDP + committed streaming FEC + jitter
run_step fec1022 env TAG=udp-1022-protected-fec UDPRATE=20M DURATION=15 \
  IPERF_LEN=256 \
  QF_E2E_FEC_CONFIG="$FEC_STREAMING" \
  QUICFUSCATE_STEALTH_JITTER_US=5000 \
  QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS=600000 \
  "$SCRIPT_DIR/tun-e2e-omega-udp.sh"

# 5. TODO-1019 uplink-heavy TCP
run_step tcp_up env TAG=tcp-1019-up DURATION=15 \
  QUICFUSCATE_STEALTH_JITTER_US=5000 \
  "$SCRIPT_DIR/tun-e2e-omega-tcp.sh"

# 6. TODO-1019 downlink-heavy TCP
run_step tcp_down env TAG=tcp-1019-down DURATION=15 \
  IPERF_REVERSE=1 \
  QUICFUSCATE_STEALTH_JITTER_US=5000 \
  "$SCRIPT_DIR/tun-e2e-omega-tcp.sh"

echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$SUMMARY"
echo "PASS: omega batch wrote $SUMMARY"
cat "$SUMMARY"
