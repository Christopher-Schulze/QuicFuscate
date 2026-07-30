#!/usr/bin/env bash
# Native Linux traffic-analysis proof over the exact QuicFuscate artifact.
# Captures authenticated client-to-server 1-RTT traffic after handshake and
# verifies idle chaff cadence, constant-rate cadence, exact UDP payload sizes,
# explicit bandwidth warnings, CPU cost, artifact identity, and owned teardown.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
BASE_E2E="$SCRIPT_DIR/tun-e2e-netns.sh"
OUTPUT_DIR="${QF_TRAFFIC_OUTPUT_DIR:-$PROJECT_ROOT/scripts/out/tests/traffic-analysis-$(date +%Y%m%d_%H%M%S)}"
CAPTURE_SECONDS="${QF_TRAFFIC_CAPTURE_SECONDS:-10}"
MAX_CPU_PERCENT="${QF_TRAFFIC_MAX_CPU_PERCENT:-25}"
WORK_DIR=""
BASELINE_PRODUCT_PIDS=""

cleanup() {
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
    WORK_DIR=""
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if [ "$(uname -s)" != "Linux" ]; then
  fail "native traffic-analysis capture requires Linux network namespaces"
fi
if [ "$(id -u)" -ne 0 ]; then
  fail "native traffic-analysis capture requires root"
fi
for command_name in awk getconf ip openssl python3 sha256sum tcpdump; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing required command: $command_name"
done
if [ ! -x "$BINARY" ]; then
  fail "exact artifact is not executable: $BINARY"
fi
if ! [[ "$CAPTURE_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  fail "QF_TRAFFIC_CAPTURE_SECONDS must be a positive integer"
fi
if ! awk -v value="$MAX_CPU_PERCENT" 'BEGIN { exit !(value > 0) }'; then
  fail "QF_TRAFFIC_MAX_CPU_PERCENT must be greater than zero"
fi
if [ -e "$OUTPUT_DIR" ]; then
  fail "output directory already exists; refusing to overwrite $OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"
WORK_DIR="$(mktemp -d /tmp/quicfuscate-traffic-analysis.XXXXXX)"
ARTIFACT_SHA256="$(sha256sum "$BINARY" | awk '{print $1}')"
BASELINE_PRODUCT_PIDS="$(pgrep -x quicfuscate 2>/dev/null | sort -n || true)"
printf '%s  %s\n' "$ARTIFACT_SHA256" "$BINARY" > "$OUTPUT_DIR/artifact.sha256"

write_policy_config() {
  local path="$1"
  local defense="$2"
  local chaff_rate_pps="$3"
  local constant_rate_pps="$4"
  cat > "$path" <<EOF
[transport.traffic_analysis]
defense = "$defense"
chaff_rate_pps = $chaff_rate_pps
chaff_size_bytes = 1280
constant_rate_pps = $constant_rate_pps
idle_timeout_ms = 60000
ramp_down_ms = 0
EOF
}

analyze_capture() {
  local case_name="$1"
  local pcap="$2"
  local expected_rate="$3"
  local expected_size="$4"
  local case_log="$5"
  local packet_table="$OUTPUT_DIR/${case_name}-packets.tsv"
  local packet_count
  local wrong_size_count
  local mean_interval_ms
  local observed_bits_per_second
  local minimum_count
  local maximum_count
  local cpu_percent
  local capture_start_epoch
  local capture_end_epoch
  local first_packet_epoch
  local last_packet_epoch
  local head_gap_ms
  local tail_gap_ms
  local maximum_boundary_gap_ms
  local reverse_packet_count

  capture_start_epoch="$(
    awk '/TRAFFIC_CAPTURE/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^capture_start_epoch=/) {
          split($i, value, "=")
          print value[2]
        }
      }
    }' "$case_log" | tail -1
  )"
  capture_end_epoch="$(
    awk '/TRAFFIC_CAPTURE/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^capture_end_epoch=/) {
          split($i, value, "=")
          print value[2]
        }
      }
    }' "$case_log" | tail -1
  )"
  if [ -z "$capture_start_epoch" ] || [ -z "$capture_end_epoch" ]; then
    fail "$case_name did not report an exact capture window"
  fi
  tcpdump -tt -n -r "$pcap" \
    'udp and src host 10.10.0.2 and dst host 10.10.0.1 and dst port 4433' 2>/dev/null |
    awk -v start="$capture_start_epoch" -v end="$capture_end_epoch" \
      '/UDP, length [0-9]+$/ && $1 >= start && $1 <= end { print $1 "\t" $NF }' \
      > "$packet_table"
  packet_count="$(wc -l < "$packet_table" | tr -d ' ')"
  wrong_size_count="$(awk -v expected="$expected_size" '$2 != expected { count++ } END { print count + 0 }' "$packet_table")"
  minimum_count="$((expected_rate * CAPTURE_SECONDS * 90 / 100))"
  maximum_count="$((expected_rate * CAPTURE_SECONDS * 110 / 100))"

  if [ "$packet_count" -lt "$minimum_count" ] || [ "$packet_count" -gt "$maximum_count" ]; then
    fail "$case_name cadence count $packet_count is outside [$minimum_count,$maximum_count]"
  fi
  if [ "$wrong_size_count" -ne 0 ]; then
    fail "$case_name contains $wrong_size_count packets not exactly ${expected_size}B"
  fi
  first_packet_epoch="$(awk 'NR == 1 { print $1 }' "$packet_table")"
  last_packet_epoch="$(awk 'END { print $1 }' "$packet_table")"
  head_gap_ms="$(
    awk -v start="$capture_start_epoch" -v first="$first_packet_epoch" \
      'BEGIN { printf "%.3f", (first - start) * 1000 }'
  )"
  tail_gap_ms="$(
    awk -v end="$capture_end_epoch" -v last="$last_packet_epoch" \
      'BEGIN { printf "%.3f", (end - last) * 1000 }'
  )"
  maximum_boundary_gap_ms="$((5000 / expected_rate))"
  if ! awk -v head="$head_gap_ms" -v tail="$tail_gap_ms" \
    -v ceiling="$maximum_boundary_gap_ms" \
    'BEGIN { exit !(head >= 0 && head <= ceiling && tail >= 0 && tail <= ceiling) }'; then
    fail "$case_name does not cover the complete capture window: head=${head_gap_ms}ms tail=${tail_gap_ms}ms ceiling=${maximum_boundary_gap_ms}ms"
  fi
  reverse_packet_count="$(
    tcpdump -tt -n -r "$pcap" \
      'udp and src host 10.10.0.1 and src port 4433 and dst host 10.10.0.2' 2>/dev/null |
      awk -v start="$capture_start_epoch" -v end="$capture_end_epoch" \
        '/UDP, length [0-9]+$/ && $1 >= start && $1 <= end { count++ } END { print count + 0 }'
  )"
  if [ "$reverse_packet_count" -eq 0 ]; then
    fail "$case_name captured no reverse ACK/control traffic"
  fi

  mean_interval_ms="$(
    awk '
      NR == 1 { previous = $1; next }
      { sum += ($1 - previous) * 1000; count++; previous = $1 }
      END { if (count == 0) print "0.000"; else printf "%.3f", sum / count }
    ' "$packet_table"
  )"
  if ! awk -v observed="$mean_interval_ms" -v rate="$expected_rate" \
    'BEGIN {
      expected = 1000 / rate
      exit !(observed >= expected * 0.90 && observed <= expected * 1.10)
    }'; then
    fail "$case_name mean interval ${mean_interval_ms}ms is outside 10% of target"
  fi

  observed_bits_per_second="$((packet_count * expected_size * 8 / CAPTURE_SECONDS))"
  if [ "$observed_bits_per_second" -gt "$((expected_rate * expected_size * 8 * 110 / 100))" ]; then
    fail "$case_name observed bandwidth ${observed_bits_per_second}bps exceeds bounded cost"
  fi
  if ! grep -q 'traffic-analysis defense enabled:' /tmp/ns-cli.log; then
    fail "$case_name did not emit the explicit traffic-analysis bandwidth warning"
  fi
  cpu_percent="$(
    awk '
      /TRAFFIC_CAPTURE/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^client_cpu_percent=/) {
            split($i, value, "=")
            print value[2]
          }
        }
      }
    ' "$case_log" | tail -1
  )"
  if [ -z "$cpu_percent" ]; then
    fail "$case_name did not report client CPU cost"
  fi
  if ! awk -v observed="$cpu_percent" -v ceiling="$MAX_CPU_PERCENT" \
    'BEGIN { exit !(observed <= ceiling) }'; then
    fail "$case_name client CPU ${cpu_percent}% exceeds ${MAX_CPU_PERCENT}%"
  fi

  cp /tmp/ns-cli.log "$OUTPUT_DIR/${case_name}-client.log"
  cp /tmp/ns-srv.log "$OUTPUT_DIR/${case_name}-server.log"
  printf '%s\n' \
    "artifact_sha256=$ARTIFACT_SHA256" \
    "capture_seconds=$CAPTURE_SECONDS" \
    "packet_count=$packet_count" \
    "reverse_packet_count=$reverse_packet_count" \
    "expected_rate_pps=$expected_rate" \
    "mean_interval_ms=$mean_interval_ms" \
    "head_gap_ms=$head_gap_ms" \
    "tail_gap_ms=$tail_gap_ms" \
    "udp_payload_bytes=$expected_size" \
    "observed_bits_per_second=$observed_bits_per_second" \
    "client_cpu_percent=$cpu_percent" \
    > "$OUTPUT_DIR/${case_name}-metrics.txt"
}

run_case() {
  local case_name="$1"
  local defense="$2"
  local chaff_rate_pps="$3"
  local constant_rate_pps="$4"
  local expected_rate="$5"
  local expected_size="$6"
  local config="$WORK_DIR/${case_name}.toml"
  local pcap="$OUTPUT_DIR/${case_name}.pcap"
  local case_log="$OUTPUT_DIR/${case_name}-run.log"

  write_policy_config "$config" "$defense" "$chaff_rate_pps" "$constant_rate_pps"
  echo "=== traffic-analysis case: $case_name ==="
  QF_E2E_BINARY="$BINARY" \
  QF_E2E_CLIENT_CONFIG="$config" \
  QF_E2E_TRAFFIC_CAPTURE_FILE="$pcap" \
  QF_E2E_TRAFFIC_CAPTURE_SECONDS="$CAPTURE_SECONDS" \
  QF_E2E_ALLOW_EXISTING_RUNTIME=1 \
    "$BASE_E2E" 2>&1 | tee "$case_log"
  analyze_capture "$case_name" "$pcap" "$expected_rate" "$expected_size" "$case_log"
}

run_case "idle-chaff-10pps" "full-padding" 10 100 10 1500
run_case "constant-rate-100pps" "constant-rate" 0 100 100 1280

FINAL_PRODUCT_PIDS="$(pgrep -x quicfuscate 2>/dev/null | sort -n || true)"
if [ "$FINAL_PRODUCT_PIDS" != "$BASELINE_PRODUCT_PIDS" ]; then
  fail "product process set changed across traffic-analysis cases"
fi
if ip netns list | grep -Eq '^(ns-srv|ns-cli)([[:space:]]|$)'; then
  fail "network namespace residue remains after traffic-analysis cases"
fi

echo "PASS: native traffic-analysis proof complete"
echo "artifact_sha256=$ARTIFACT_SHA256"
echo "evidence_dir=$OUTPUT_DIR"
