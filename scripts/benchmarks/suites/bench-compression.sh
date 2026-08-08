#!/usr/bin/env bash
# Description: Compression micro-benchmark harness (text/binary payloads)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
ITER=50
SIZE=$((256 * 1024))
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iterations) ITER="$2"; shift;;
    --size) SIZE="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--iterations N] [--size BYTES]"
      usage_common_flags 2>/dev/null || true
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
  shift
done

TS=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$ROOT/scripts/out/benchmarks/bench-compression-$TS"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/bench.log"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "bench_compression"; JSON_FIRST_RUN=1
FAILURES=0

run_bench() {
  local mode="$1"
  local outfile="$OUTPUT_DIR/${mode}.json"
  echo "[bench] mode=$mode size=$SIZE iterations=$ITER"
  local command_status=0
  local result="PASS"
  local reason=""
  local metric_value="null"
  if qf_benchmark_run "$outfile" run cargo run --release --example compress_bench -- \
    --dataset "$mode" \
    --size "$SIZE" \
    --iterations "$ITER" \
    --json; then
    command_status=0
    result="PASS"
    reason=""
  else
    command_status="$QF_BENCH_COMMAND_STATUS"
    result="FAIL"
    reason="benchmark_command_failed"
    FAILURES=$((FAILURES + 1))
  fi
  duration_sec="$QF_BENCH_DURATION_SEC"
  if [[ "$result" == "PASS" ]]; then
    parsed_metric=""
    if parsed_metric="$(python3 - "$outfile" "$mode" "$SIZE" "$ITER" <<'PY'
import json
import math
import sys
from pathlib import Path

path, expected_mode, expected_size, expected_iterations = sys.argv[1:]
document = json.loads(Path(path).read_text(encoding="utf-8"))
if document.get("dataset") != expected_mode:
    raise SystemExit("dataset identity mismatch")
if int(document.get("payload_bytes", 0)) != int(expected_size):
    raise SystemExit("payload size identity mismatch")
if int(document.get("iterations", 0)) != int(expected_iterations):
    raise SystemExit("iteration identity mismatch")
successes = int(document.get("successes", 0))
if successes <= 0:
    raise SystemExit("compression produced no successful samples")
throughput = float(document.get("throughput_mib_s", "nan"))
if not math.isfinite(throughput) or throughput < 0:
    raise SystemExit("throughput metric is not finite")
print(throughput)
PY
)"; then
      metric_value="float:$parsed_metric"
    else
      result="FAIL"
      reason="invalid_benchmark_result"
      FAILURES=$((FAILURES + 1))
    fi
  fi
  qf_benchmark_record "$RESULTS_JSON" "compression/${mode}" "throughput_mib_s" "$metric_value" \
    "$result" "$reason" "$command_status" "compress_bench" "default" "$outfile" \
    "$(qf_json_array cargo run --release --example compress_bench -- --dataset "$mode" --size "$SIZE" --iterations "$ITER" --json)" \
    "$(qf_json_environment)" "int:$duration_sec"
  cat "$outfile"
  echo "  -> $outfile"
}

run_bench text
run_bench binary

json_end "$RESULTS_JSON"
echo "Artifacts stored in $OUTPUT_DIR"
if [[ "$FAILURES" -gt 0 ]]; then
  echo "[FAIL] $FAILURES compression benchmark cells failed" >&2
  exit 1
fi
