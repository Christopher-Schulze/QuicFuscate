#!/usr/bin/env bash
# Description: Retained crypto backend evidence runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# The source path is rooted through SCRIPT_DIR at runtime.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../../tests/lib/lib-common.sh" || { echo "ERROR: lib-common.sh not found" >&2; exit 1; }

OUTPUT_DIR=""
FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--fast]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/bench-retained-crypto-backends-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
CSV_FILE="$OUTPUT_DIR/results.csv"
RESULTS_JSON="$OUTPUT_DIR/results.json"
json_begin "$RESULTS_JSON" "bench_retained_crypto_backends"
FAILURES=0

if (( FAST )); then
  SIZES=("1200B" "16KiB" "64KiB")
  ITERS=200
else
  SIZES=("1200B" "4KiB" "16KiB" "64KiB")
  ITERS=1000
fi

BACKENDS=("aegis128l" "aegis128x4" "aegis128x8" "morus1280_128")

{
  echo "suite=bench-retained-crypto-backends"
  echo "output_dir=$OUTPUT_DIR"
  echo "iters=$ITERS"
  echo "sizes=${SIZES[*]}"
} > "$SUMMARY_FILE"

PROFILE_OUTPUT="$OUTPUT_DIR/profile.txt"
if qf_benchmark_run "$PROFILE_OUTPUT" run cargo run --release --features benches --quiet --example crypto_backend_bench -- profile; then
  profile_status=0
  profile_result="PASS"
  profile_reason=""
else
  profile_status="$QF_BENCH_COMMAND_STATUS"
  profile_result="FAIL"
  profile_reason="profile_command_failed"
  FAILURES=$((FAILURES + 1))
fi
PROFILE_LINE="$(<"$PROFILE_OUTPUT")"
echo "$PROFILE_LINE" > "$OUTPUT_DIR/profile.txt"
echo "$PROFILE_LINE" >> "$SUMMARY_FILE"
qf_benchmark_record "$RESULTS_JSON" "profile" "duration_sec" "int:$QF_BENCH_DURATION_SEC" \
  "$profile_result" "$profile_reason" "$profile_status" "crypto_backend_bench" "benches" \
  "$PROFILE_OUTPUT" "$(qf_json_array cargo run --release --features benches --quiet --example crypto_backend_bench -- profile)" \
  "$(qf_json_environment)"

echo "backend,size,mbps,instantiations" > "$CSV_FILE"

run_one() {
  local backend="$1"
  local size="$2"
  local line
  local output_file="$OUTPUT_DIR/${backend}-${size}.txt"
  local command_status=0
  if qf_benchmark_run "$output_file" run cargo run --release --features benches --quiet --example crypto_backend_bench -- run "$backend" "$size" "$ITERS"; then
    command_status=0
  else
    command_status="$QF_BENCH_COMMAND_STATUS"
  fi
  local line
  line="$(<"$output_file")"
  local parsed=""
  if [[ "$command_status" -eq 0 ]]; then
    parsed="$(python3 - "$line" "$backend" "$size" "$ITERS" <<'PY'
import math
import sys

line, expected_backend, expected_size, expected_iters = sys.argv[1:]
fields = line.split(",")
values = dict(zip(fields[::2], fields[1::2])) if len(fields) % 2 == 0 else {}
if values.get("bench") != "crypto-backend" or values.get("backend") != expected_backend:
    raise SystemExit("backend identity mismatch")
if int(values.get("iters", "0")) != int(expected_iters):
    raise SystemExit("iteration identity mismatch")
bytes_value = int(values.get("bytes", "0"))
if bytes_value <= 0:
    raise SystemExit("processed byte count is not positive")
mbps = float(values.get("mbps", "nan"))
if not math.isfinite(mbps) or mbps < 0:
    raise SystemExit("mbps is not finite")
print(f"{mbps}\t{values.get('instantiations', '0')}")
PY
)" || parsed=""
  fi
  local result="PASS"
  local reason=""
  local mbps="null"
  local instantiations="null"
  if [[ "$command_status" -ne 0 ]]; then
    result="FAIL"
    reason="benchmark_command_failed"
    FAILURES=$((FAILURES + 1))
  elif [[ -z "$parsed" ]]; then
    result="FAIL"
    reason="invalid_backend_result"
    FAILURES=$((FAILURES + 1))
  else
    IFS=$'\t' read -r mbps instantiations <<< "$parsed"
  fi
  echo "${backend},${size},${mbps},${instantiations}" >> "$CSV_FILE"
  local metric_value="null"
  [[ "$result" == "PASS" ]] && metric_value="float:$mbps"
  qf_benchmark_record "$RESULTS_JSON" "backend/${backend}/${size}" "mbps" "$metric_value" \
    "$result" "$reason" "$command_status" "crypto_backend_bench" "benches" "$output_file" \
    "$(qf_json_array cargo run --release --features benches --quiet --example crypto_backend_bench -- run "$backend" "$size" "$ITERS")" \
    "$(qf_json_environment)"
}

for size in "${SIZES[@]}"; do
  for backend in "${BACKENDS[@]}"; do
    run_one "$backend" "$size"
  done
done

if ! python3 - "$CSV_FILE" "$SUMMARY_FILE" <<'PY'
import csv
import math
import sys
from collections import defaultdict

csv_path, summary_path = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(csv_path, newline="")))
by_size = defaultdict(list)
for row in rows:
    try:
        value = float(row["mbps"])
    except (TypeError, ValueError):
        continue
    if not math.isfinite(value) or value < 0:
        continue
    by_size[row["size"]].append(row)

with open(summary_path, "a") as out:
    expected_sizes = {row["size"] for row in rows}
    missing = sorted(expected_sizes - by_size.keys())
    if missing:
        raise SystemExit(f"no valid retained-backend metric for sizes: {missing}")
    for size, items in by_size.items():
        best = max(items, key=lambda row: float(row["mbps"]))
        out.write(f"best_backend[{size}]={best['backend']}\n")
        out.write(f"best_mbps[{size}]={best['mbps']}\n")
PY
then
  FAILURES=$((FAILURES + 1))
  echo "[FAIL] retained-backend summary could not be derived from valid metrics" >&2
fi

if [[ "$FAILURES" -eq 0 ]]; then
  echo "ok=1" >> "$SUMMARY_FILE"
else
  echo "ok=0" >> "$SUMMARY_FILE"
fi
echo "failed=$FAILURES" >> "$SUMMARY_FILE"
echo "$OUTPUT_DIR"
json_end "$RESULTS_JSON"
if [[ "$FAILURES" -gt 0 ]]; then
  exit 1
fi
