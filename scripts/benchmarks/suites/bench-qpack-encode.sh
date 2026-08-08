#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-qpack-encode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA="-C target-cpu=native"; FAST=0; SIZES_INPUT="64k 256k 1m"; SIZES_EXPLICIT=0; JSON=""; JOBS=""; FEATURES="";
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --sizes) SIZES_INPUT="$2"; SIZES_EXPLICIT=1; shift;;
    --features) FEATURES="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast] [--sizes '64k 256k 1m'] [--features STR] [--jobs N]"; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_qpack_encode"; JSON_FIRST_RUN=1

append_item() {
  local cell="$1"; local size="$2"; local metric_value="$3"; local result="$4"
  local reason="$5"; local command_status="$6"; local output_file="$7"
  local argv_json="${8:-[]}"
  qf_benchmark_record "$JSON" "qpack/$cell/$size" "throughput_MiBps" "$metric_value" "$result" "$reason" \
    "$command_status" "harness" "${FEATURES:-default}" "$output_file" "$argv_json" "$(qf_json_environment)"
}

if ! validate_control_free_value "RUSTFLAGS_EXTRA" "$RUSTFLAGS_EXTRA" 8192 || \
   ! validate_feature_list "features" "$FEATURES" || \
   { [[ -n "$JOBS" ]] && ! validate_positive_int "jobs" "$JOBS" 64; }; then
  append_item 0 "<input>" null "FAIL" "invalid_cli_input" 2 ""
  json_end "$JSON"
  exit 2
fi
[[ -n "$FEATURES" ]] && export CARGO_FEATURES="$FEATURES"
[[ -n "$JOBS" ]] && export JOBS

print_system_banner

# Fast mode reduces sizes
if [[ "$FAST" -eq 1 && "$SIZES_EXPLICIT" -eq 0 ]]; then
  SIZES_INPUT="64k 256k"
fi

read -r -a SIZES <<< "$SIZES_INPUT"
if [[ "${#SIZES[@]}" -eq 0 ]]; then
  append_item 0 "<input>" null "FAIL" "empty_size_list" 2 ""
  json_end "$JSON"
  exit 2
fi

size_to_bytes() {
  local s="$1"; local base; local value
  case "$s" in
    *k|*K)
      base="${s%[kK]}"
      [[ "$base" =~ ^[0-9]+$ ]] || return 2
      value=$((10#$base))
      (( value > 0 && value <= 65536 )) || return 2
      printf '%s\n' "$((value * 1024))"
      ;;
    *m|*M)
      base="${s%[mM]}"
      [[ "$base" =~ ^[0-9]+$ ]] || return 2
      value=$((10#$base))
      (( value > 0 && value <= 64 )) || return 2
      printf '%s\n' "$((value * 1024 * 1024))"
      ;;
    *)
      [[ "$s" =~ ^[0-9]+$ ]] || return 2
      value=$((10#$s))
      (( value > 0 && value <= 67108864 )) || return 2
      printf '%s\n' "$value"
      ;;
  esac
}

echo "==============================================================="
echo "  QPACK Encode Benchmark (scalar vs AVX2 vs NEON)"
echo "==============================================================="

PREFLIGHT_INVALID=0
PREFLIGHT_CELL=0
for sz in "${SIZES[@]}"; do
  PREFLIGHT_CELL=$((PREFLIGHT_CELL + 1))
  if ! size_to_bytes "$sz" >/dev/null; then
    append_item "$PREFLIGHT_CELL" "$sz" null "FAIL" "invalid_size" 2 ""
    PREFLIGHT_INVALID=$((PREFLIGHT_INVALID + 1))
  fi
done
if [[ "$PREFLIGHT_INVALID" -gt 0 ]]; then
  json_end "$JSON"
  exit 2
fi

info "Building developer harness (src/bin/harness.rs)"
BUILD_STATUS=0
BUILD_OUTPUT="$OUTPUT_DIR/build.log"
if qf_benchmark_run "$BUILD_OUTPUT" run_cargo build --release; then
  BUILD_STATUS=0
else
  BUILD_STATUS="$QF_BENCH_COMMAND_STATUS"
fi
cat "$BUILD_OUTPUT"
if [[ "$BUILD_STATUS" -ne 0 ]]; then
  append_item 0 "<build>" null "FAIL" "harness_build_failed" "$BUILD_STATUS" ""
  CELL=0
  for sz in "${SIZES[@]}"; do
    CELL=$((CELL + 1))
    append_item "$CELL" "$sz" null "FAIL" "harness_build_failed" "$BUILD_STATUS" "$BUILD_OUTPUT" \
      "$(qf_json_array cargo build --release)"
  done
  json_end "$JSON"
  exit "$BUILD_STATUS"
fi

FAILURES=0
CELL=0
for sz in "${SIZES[@]}"; do
  CELL=$((CELL + 1))
  if BYTES="$(size_to_bytes "$sz")"; then
    :
  else
    info "Rejecting invalid size=$sz"
    append_item "$CELL" "$sz" null "FAIL" "invalid_size" 2 ""
    FAILURES=$((FAILURES + 1))
    continue
  fi
  info "Running size=$sz ($BYTES bytes)"
  output_file="$OUTPUT_DIR/run-${CELL}.txt"
  command_status=0
  if qf_benchmark_run "$output_file" target/release/harness qpack-encode --input "$BYTES" --iters 200; then
    result="PASS"
    reason=""
  else
    command_status="$QF_BENCH_COMMAND_STATUS"
    result="FAIL"
    reason="harness_command_failed"
    FAILURES=$((FAILURES + 1))
  fi
  metric_value="null"
  if [[ "$result" == "PASS" ]]; then
    if throughput="$(python3 - "$output_file" "$BYTES" <<'PY'
import math
import re
import sys
from pathlib import Path

path, expected_size = sys.argv[1:]
line = Path(path).read_text(encoding="utf-8").strip()
match = re.fullmatch(
    r"variant=dispatch size=(?P<size>\d+)B iters=(?P<iters>\d+) total_out=(?P<total>\d+)B "
    r"time_ms=(?P<time>[0-9.]+) throughput_MiBps=(?P<throughput>[0-9.]+) warmup_ms=(?P<warmup>[0-9.]+)",
    line,
)
if match is None:
    raise SystemExit("unexpected QPACK harness output")
if int(match.group("size")) != int(expected_size) or int(match.group("iters")) != 200:
    raise SystemExit("QPACK workload identity mismatch")
if int(match.group("total")) <= 0:
    raise SystemExit("QPACK output byte count is not positive")
value = float(match.group("throughput"))
if not math.isfinite(value) or value < 0:
    raise SystemExit("QPACK throughput is not finite")
print(value)
PY
)"; then
      metric_value="float:$throughput"
    else
      result="FAIL"
      reason="invalid_benchmark_result"
      FAILURES=$((FAILURES + 1))
    fi
  fi
  cat "$output_file"
  append_item "$CELL" "$sz" "$metric_value" "$result" "$reason" "$command_status" "$output_file" \
    "$(qf_json_array target/release/harness qpack-encode --input "$BYTES" --iters 200)"

done

json_end "$JSON"
info "Results JSON: $JSON"
if [[ "$FAILURES" -gt 0 ]]; then
  info "Completed with ${FAILURES} failed cells."
  exit 1
fi
info "Done."
