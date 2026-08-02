#!/usr/bin/env bash
# Description: Test suite runner: test-runtime-soak-chaos.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
DRY_RUN=""
ITERATIONS=2
ADMIN_ITERATIONS=1
START_EPOCH="$(date +%s)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iterations) ITERATIONS="$2"; shift;;
    --admin-iterations) ADMIN_ITERATIONS="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--iterations N] [--admin-iterations N] [--fast] [--dry-run]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if (( FAST )); then
  ITERATIONS=1
  ADMIN_ITERATIONS=1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "tests_runtime_soak_chaos"
JSON_FIRST_RUN=1

append_item() {
  local name="$1"
  local status="$2"
  local details="$3"
  qf_json_append_object "$JSON" "name=$name" "status=$status" "details=$details"
}

echo "==============================================================="
echo "  Runtime Soak and Chaos Validation"
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

for iter in $(seq 1 "$ITERATIONS"); do
  run_case \
    "steady_integration_iter_${iter}" \
    "$OUTPUT_DIR/steady_integration_${iter}" \
    "$SCRIPT_DIR/test-e2e.sh" --integration \
    --fast \
    --output-dir "$OUTPUT_DIR/steady_integration_${iter}"

  run_case \
    "fec_loss_chaos_iter_${iter}" \
    "$OUTPUT_DIR/fec_loss_chaos_${iter}" \
    "$SCRIPT_DIR/test-fec-e2e-loss.sh" \
    --fast \
    --output-dir "$OUTPUT_DIR/fec_loss_chaos_${iter}"
done

for iter in $(seq 1 "$ADMIN_ITERATIONS"); do
  run_case \
    "admin_qkey_iter_${iter}" \
    "$OUTPUT_DIR/admin_qkey_${iter}" \
    env QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1 \
    "$SCRIPT_DIR/test-e2e-admin-web.sh" \
    --output-dir "$OUTPUT_DIR/admin_qkey_${iter}"
done

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

items = data.get("items", [])
ok = sum(1 for item in items if item.get("status") == "ok")
failed = sum(1 for item in items if item.get("status") == "fail")
dry = sum(1 for item in items if item.get("status") == "dry-run")
steady_ok = sum(1 for item in items if item.get("status") == "ok" and item.get("name", "").startswith("steady_integration_"))
steady_failed = sum(1 for item in items if item.get("status") == "fail" and item.get("name", "").startswith("steady_integration_"))
fec_ok = sum(1 for item in items if item.get("status") == "ok" and item.get("name", "").startswith("fec_loss_chaos_"))
fec_failed = sum(1 for item in items if item.get("status") == "fail" and item.get("name", "").startswith("fec_loss_chaos_"))
admin_ok = sum(1 for item in items if item.get("status") == "ok" and item.get("name", "").startswith("admin_qkey_"))
admin_failed = sum(1 for item in items if item.get("status") == "fail" and item.get("name", "").startswith("admin_qkey_"))

lines = [
    "Runtime Soak/Chaos Summary",
    f"ok={ok}",
    f"failed={failed}",
    f"dry_run={dry}",
    f"steady_ok={steady_ok}",
    f"steady_failed={steady_failed}",
    f"fec_ok={fec_ok}",
    f"fec_failed={fec_failed}",
    f"admin_ok={admin_ok}",
    f"admin_failed={admin_failed}",
]
for item in items:
    lines.append(f"{item.get('name', '<unnamed>')}: {item.get('status', '?')} -> {item.get('details', '')}")

try:
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
except OSError as e:
    print(f"Failed to write {sys.argv[2]}: {e}", file=sys.stderr)
PY

END_EPOCH="$(date +%s)"
ELAPSED="$(( END_EPOCH - START_EPOCH ))"
echo "elapsed_seconds=$ELAPSED" >> "$SUMMARY_FILE"

echo -e "\n[OK] Runtime soak/chaos suite complete. Artifacts: $OUTPUT_DIR"
