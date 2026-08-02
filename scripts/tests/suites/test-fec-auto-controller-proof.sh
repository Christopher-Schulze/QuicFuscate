#!/usr/bin/env bash
# Description: Test suite runner: test-fec-auto-controller-proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
DRY_RUN=""
SCENARIO_ITERATIONS=1
BENCH_ITERATIONS=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --scenario-iterations) SCENARIO_ITERATIONS="$2"; shift;;
    --bench-iterations) BENCH_ITERATIONS="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--scenario-iterations N] [--bench-iterations N] [--fast] [--dry-run]"
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
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "tests_fec_auto_controller_proof"
JSON_FIRST_RUN=1

append_item() {
  local name="$1"
  local status="$2"
  local details="$3"
  qf_json_append_object "$JSON" "name=$name" "status=$status" "details=$details"
}

echo "==============================================================="
echo "  FEC Auto-Controller Proof"
echo "==============================================================="

run_case() {
  local name="$1"
  shift
  local out_dir="$1"
  shift
  echo -e "\n> $name"
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "DRY-RUN: $*"
    append_item "$name" "dry-run" "$out_dir"
    return 0
  fi
  if "$@"; then
    append_item "$name" "ok" "$out_dir"
    return 0
  fi
  append_item "$name" "fail" "$out_dir"
  return 1
}

SCENARIO_OUT="$OUTPUT_DIR/scenarios"
BENCH_OUT="$OUTPUT_DIR/bench"

SCENARIO_ARGS=("--output-dir" "$SCENARIO_OUT")
BENCH_ARGS=("--output-dir" "$BENCH_OUT")
if (( FAST )); then
  BENCH_ARGS+=("--fast")
fi

for iter in $(seq 1 "$SCENARIO_ITERATIONS"); do
  run_case \
    "controller_scenarios_iter_${iter}" \
    "$SCENARIO_OUT/iter_${iter}" \
    bash \
    "$SCRIPT_DIR/test-fec-auto-controller-scenarios.sh" \
    --output-dir "$SCENARIO_OUT/iter_${iter}"
done

for iter in $(seq 1 "$BENCH_ITERATIONS"); do
  run_case \
    "controller_bench_iter_${iter}" \
    "$BENCH_OUT/iter_${iter}" \
    bash \
    "$PROJECT_ROOT/scripts/benchmarks/suites/bench-fec-simulation.sh" \
    --output-dir "$BENCH_OUT/iter_${iter}" \
    "${BENCH_ARGS[@]:2}"
done

json_end "$JSON"

SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
python3 - "$JSON" "$SUMMARY_FILE" <<'PY'
import json
import sys
from pathlib import Path

if len(sys.argv) < 3:
    print("usage: script.py <json_file> <summary_file>", file=sys.stderr)
    sys.exit(1)

try:
    data = json.loads(Path(sys.argv[1]).read_text())
except (OSError, json.JSONDecodeError) as e:
    print(f"error reading JSON results: {e}", file=sys.stderr)
    sys.exit(1)

items = data.get("items", [])
ok = sum(1 for item in items if item.get("status") == "ok")
failed = sum(1 for item in items if item.get("status") == "fail")
dry = sum(1 for item in items if item.get("status") == "dry-run")
scenario_ok = sum(1 for item in items if item.get("status") == "ok" and item.get("name", "").startswith("controller_scenarios_"))
scenario_failed = sum(1 for item in items if item.get("status") == "fail" and item.get("name", "").startswith("controller_scenarios_"))
bench_ok = sum(1 for item in items if item.get("status") == "ok" and item.get("name", "").startswith("controller_bench_"))
bench_failed = sum(1 for item in items if item.get("status") == "fail" and item.get("name", "").startswith("controller_bench_"))

clean_efficiency_ok = 0
escalation_ok = 0
cadence_ok = 0
backend_family_ok = 0
stability_ok = 0
recovery_ok = 0
for item in items:
    if not item.get("name", "").startswith("controller_scenarios_"):
        continue
    summary_path = Path(item.get("details", "")) / "summary.txt"
    if not summary_path.exists():
        continue
    try:
        summary_map = {}
        for line in summary_path.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                summary_map[key] = value
        clean_efficiency_ok += int(summary_map.get("clean_efficiency_ok", "0"))
        escalation_ok += int(summary_map.get("escalation_ok", "0"))
        cadence_ok += int(summary_map.get("cadence_ok", "0"))
        backend_family_ok += int(summary_map.get("backend_family_ok", "0"))
        stability_ok += int(summary_map.get("stability_ok", "0"))
        recovery_ok += int(summary_map.get("recovery_ok", "0"))
    except (OSError, ValueError) as e:
        print(f"warning: skipping summary {summary_path}: {e}", file=sys.stderr)
        continue

lines = [
    "FEC Auto-Controller Proof Summary",
    f"ok={ok}",
    f"failed={failed}",
    f"dry_run={dry}",
    f"scenario_ok={scenario_ok}",
    f"scenario_failed={scenario_failed}",
    f"bench_ok={bench_ok}",
    f"bench_failed={bench_failed}",
    f"clean_efficiency_ok={clean_efficiency_ok}",
    f"escalation_ok={escalation_ok}",
    f"cadence_ok={cadence_ok}",
    f"backend_family_ok={backend_family_ok}",
    f"stability_ok={stability_ok}",
    f"recovery_ok={recovery_ok}",
]
for item in items:
    lines.append(f"{item['name']}: {item['status']} -> {item['details']}")

try:
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
except OSError as e:
    print(f"error writing summary: {e}", file=sys.stderr)
    sys.exit(1)
PY

echo -e "\n[OK] FEC auto-controller proof complete. Artifacts: $OUTPUT_DIR"
