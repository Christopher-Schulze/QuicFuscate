#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-linux-send-path-decision.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
ITERS=10000
BATCH=32
SIZES="1200,4096,16384"
DRY_RUN=""

usage() {
  cat <<USAGE
Linux send-path benchmark harness

Runs the canonical Linux send-path comparison matrix:
- baseline transport fast-path profile set
- io_uring profile set
- udpfast loopback micro runs over the retained plain runtime path

Usage: $(basename "$0") [options]

Options:
  --output-dir DIR   Target directory for artifacts
  --sizes CSV        Payload sizes to compare (default: 1200,4096,16384)
  --iters N          Batch iterations for udpfast micro runs (default: 10000)
  --batch N          Batch size for udpfast micro runs (default: 32)
  --fast             Reduced workload
  --dry-run          Show commands without executing
  --verbose          Enable QUICFUSCATE_DEBUG_SCRIPTS
  --help, -h         Show this help and exit
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --sizes) SIZES="$2"; shift;;
    --iters) ITERS="$2"; shift;;
    --batch) BATCH="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown flag: $1" >&2; usage; exit 2;;
  esac
  shift
done

if [[ "$(detect_os)" != "linux" ]]; then
  warn "linux send-path decision harness skipped: requires Linux host."
  exit 0
fi

if (( FAST )); then
  ITERS=2000
  BATCH=16
  SIZES="1200,4096"
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$ARTIFACTS_DIR/results.json"
json_begin "$JSON" "bench_linux_send_path_decision"
JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Linux Send-Path Benchmark Harness"
echo "==============================================================="
info "sizes=$SIZES iters=$ITERS batch=$BATCH"

run_profile_suite() {
  local subdir="$ARTIFACTS_DIR/profile-fastpaths"
  mkdir -p "$subdir"
  local cmd=("$SCRIPT_DIR/bench-profile-transport-fastpaths.sh" "--output-dir" "$subdir")
  (( FAST )) && cmd+=("--fast")
  [[ -n "$DRY_RUN" ]] && cmd+=("--dry-run")
  if [[ -n "$DRY_RUN" ]]; then
    echo "DRY-RUN: ${cmd[*]}"
    return 0
  fi
  run "${cmd[@]}"
}

run_udpfast_variant() {
  local size="$1"
  local subdir="$ARTIFACTS_DIR/udpfast-baseline-${size}"
  mkdir -p "$subdir"
  local cmd=(
    "$SCRIPT_DIR/../micro/micro-udpfast-throughput.sh"
    "--output-dir" "$subdir"
    "--size" "$size"
    "--iters" "$ITERS"
    "--batch" "$BATCH"
  )
  (( FAST )) && cmd+=("--fast")
  [[ -n "$DRY_RUN" ]] && cmd+=("--dry-run")

  if [[ -n "$DRY_RUN" ]]; then
    echo "DRY-RUN: ${cmd[*]}"
    return 0
  fi
  run "${cmd[@]}"
}

run_profile_suite

IFS=',' read -r -a SIZE_LIST <<< "$SIZES"
for size in "${SIZE_LIST[@]}"; do
  size="${size// /}"
  [[ -z "$size" ]] && continue
  info "profiling udpfast size bucket $size"
  run_udpfast_variant "$size"
done

json_end "$JSON"
SUMMARY_FILE="$ARTIFACTS_DIR/summary.txt"
DECISION_JSON="$ARTIFACTS_DIR/decision.json"
DECISION_DOCUMENT="$(python3 - "$ARTIFACTS_DIR" "$SUMMARY_FILE" <<'PY'
import json
import re
import sys
from pathlib import Path

artifacts = Path(sys.argv[1])
summary_path = Path(sys.argv[2])

line_re = re.compile(
    r"variant=udpfast size=(?P<size>\d+)B iters=(?P<iters>\d+) batch=(?P<batch>\d+) "
    r"sent_packets=(?P<sent_packets>\d+) sent_bytes=(?P<sent_bytes>\d+) recv_bytes=(?P<recv_bytes>\d+) "
    r"time_ms=(?P<time_ms>[0-9.]+) throughput_MiBps=(?P<throughput>[0-9.]+)"
)

measurements = {}
for variant_dir in sorted(artifacts.glob("udpfast-*")):
    name = variant_dir.name
    if not name.startswith("udpfast-"):
        continue
    parts = name.split("-")
    if len(parts) < 3:
        continue
    variant = "-".join(parts[1:-1])
    size = int(parts[-1])
    txt = variant_dir / "micro-udpfast-throughput.txt"
    if not txt.exists():
        continue
    for line in txt.read_text().splitlines():
        match = line_re.search(line)
        if match:
            measurements.setdefault(size, {})[variant] = {
                "throughput_mibps": float(match.group("throughput")),
                "time_ms": float(match.group("time_ms")),
                "sent_packets": int(match.group("sent_packets")),
                "sent_bytes": int(match.group("sent_bytes")),
                "recv_bytes": int(match.group("recv_bytes")),
                "iters": int(match.group("iters")),
                "batch": int(match.group("batch")),
            }

profile_info = {
    "tokio_present": (artifacts / "profile-fastpaths" / "tokio").exists(),
    "io_uring_present": (artifacts / "profile-fastpaths" / "io_uring").exists(),
}

measurements_out = []
for size in sorted(measurements):
    baseline = measurements[size].get("baseline")
    if not baseline:
        continue
    item = {
        "size": size,
        "baseline_throughput_mibps": baseline["throughput_mibps"],
        "time_ms": baseline["time_ms"],
        "sent_packets": baseline["sent_packets"],
        "sent_bytes": baseline["sent_bytes"],
        "recv_bytes": baseline["recv_bytes"],
    }
    measurements_out.append(item)

decision = {
    "schema": "quicfuscate.v1.linux_send_path_decision",
    "profile": profile_info,
    "measurements": measurements_out,
    "verdict": "benchmark-only",
    "rationale": "MSG_ZEROCOPY has been removed from the runtime. This harness records the retained Linux send-path baseline only.",
}
print(json.dumps(decision, indent=2))

lines = [
    "Linux Send-Path Benchmark Summary",
    f"tokio_profile_present={str(profile_info['tokio_present']).lower()}",
    f"io_uring_profile_present={str(profile_info['io_uring_present']).lower()}",
    "verdict=benchmark-only",
    "rationale=MSG_ZEROCOPY removed from runtime; harness records retained Linux send-path baseline only.",
]
for item in measurements_out:
    lines.append(
        "size={size} baseline_mibps={baseline:.2f} sent_packets={sent_packets} sent_bytes={sent_bytes} recv_bytes={recv_bytes}".format(
            size=item["size"],
            baseline=item["baseline_throughput_mibps"],
            sent_packets=item["sent_packets"],
            sent_bytes=item["sent_bytes"],
            recv_bytes=item["recv_bytes"],
        )
    )
summary_path.write_text("\n".join(lines) + "\n")
PY
)"
qf_json_write_raw_file "$DECISION_JSON" "$DECISION_DOCUMENT"
info "Artifacts stored under $ARTIFACTS_DIR"
