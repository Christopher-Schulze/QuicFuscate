#!/usr/bin/env bash
# Description: Test suite runner: test-fec-auto-controller-scenarios.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--dry-run] [--verbose]"
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "test_fec_auto_controller_scenarios"
JSON_FIRST_RUN=1
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==============================================================="
echo "  FEC Auto-Controller Scenario Suite"
echo "==============================================================="

append_item() {
  local name="$1"
  local status="$2"
  local details="$3"
  qf_json_append_object "$JSON" "name=$name" "status=$status" "details=$details"
}

run_named_case() {
  local name="$1"
  local filter="$2"
  local category="$3"
  echo
  info "Running ${name}"
  local start_ts end_ts elapsed
  start_ts="$(date +%s)"
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "DRY-RUN: cargo test --features rust-tests --lib ${filter}"
    append_item "$name" "dry-run" "category=${category};filter=${filter}"
    return 0
  fi
  if run cargo test --features rust-tests --lib "${filter}"; then
    end_ts="$(date +%s)"
    elapsed=$((end_ts - start_ts))
    append_item "$name" "ok" "category=${category};filter=${filter};elapsed_seconds=${elapsed}"
    return 0
  fi
  end_ts="$(date +%s)"
  elapsed=$((end_ts - start_ts))
  append_item "$name" "fail" "category=${category};filter=${filter};elapsed_seconds=${elapsed}"
  return 1
}

run_named_case "clean-link zero family" "test_continuous_target_keeps_clean_link_zero_family" "clean-efficiency"
run_named_case "disturbance escalates to streaming" "test_continuous_target_escalates_to_streaming_under_disturbance" "escalation"
run_named_case "extreme loss escalates to fountain" "test_continuous_target_escalates_to_fountain_under_extreme_loss" "escalation"
run_named_case "stream interval tracks controller target" "test_stream_interval_target_tracks_controller_target" "cadence"
run_named_case "backend low-cost gf4 path" "test_backend_family_mapping_preserves_low_cost_gf4_path" "backend-family"
run_named_case "backend heavy adaptive-rs path" "test_backend_family_mapping_preserves_heavy_block_adaptive_rs_path" "backend-family"
run_named_case "target rank monotonicity" "test_target_rank_monotonic_from_clean_to_extreme" "stability"
run_named_case "force-on promotion" "test_runtime_plan_force_on_promotes_zero_target" "stability"
run_named_case "adaptive-rs gf16 selection" "test_adaptive_rs_gf16_selection_comes_from_target_truth" "backend-family"
run_named_case "no instant downshift on single low-loss sample" "test_mode_does_not_downshift_on_single_low_loss_sample" "recovery"

json_end "$JSON"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
python3 - "$JSON" "$SUMMARY_FILE" <<'PY'
import json
import sys
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: <json_in> <summary_out>", file=sys.stderr)
    sys.exit(1)
try:
    data = json.loads(Path(sys.argv[1]).read_text())
except (OSError, ValueError) as e:
    print(f"Failed to read/parse {sys.argv[1]}: {e}", file=sys.stderr)
    sys.exit(1)

items = [
    item for item in data.get("items", [])
    if "status" in item and "details" in item
]
ok = sum(1 for item in items if item.get("status") == "ok")
failed = sum(1 for item in items if item.get("status") == "fail")
dry = sum(1 for item in items if item.get("status") == "dry-run")
categories = {
    "clean-efficiency": "clean_efficiency_ok",
    "escalation": "escalation_ok",
    "cadence": "cadence_ok",
    "backend-family": "backend_family_ok",
    "stability": "stability_ok",
    "recovery": "recovery_ok",
}
results = {v: 0 for v in categories.values()}
elapsed_total = 0
for item in items:
    details = item.get("details", "")
    parts = dict(
        piece.split("=", 1)
        for piece in details.split(";")
        if "=" in piece
    )
    category = parts.get("category")
    if item.get("status") == "ok" and category in categories:
        results[categories[category]] += 1
    elapsed_total += int(parts.get("elapsed_seconds", "0"))

lines = [
    "FEC Auto-Controller Scenario Summary",
    f"ok={ok}",
    f"failed={failed}",
    f"dry_run={dry}",
    f"elapsed_seconds={elapsed_total}",
]
for key, value in results.items():
    lines.append(f"{key}={value}")
for item in items:
    lines.append(f"{item.get('name', '<unnamed>')}: {item['status']} -> {item['details']}")

try:
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
except OSError as e:
    print(f"Failed to write {sys.argv[2]}: {e}", file=sys.stderr)
PY
info "Artifacts stored under $OUTPUT_DIR"
