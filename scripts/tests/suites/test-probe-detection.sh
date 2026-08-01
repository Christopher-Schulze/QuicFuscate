#!/usr/bin/env bash
# Description: Test suite runner: test-probe-detection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=1
SOAK_ITERS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --soak-iters) SOAK_ITERS="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "Probe Detection Validation Suite"
      usage_common_flags 2>/dev/null || true
      echo "  Additional flags:"
      echo "    --fast            Run deterministic minimum validation set"
      echo "    --soak-iters N    Re-run probe invariants N times for extended validation"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Probe Detection Validation Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

RESULTS_JSON="$OUTPUT_DIR/results.json"
json_begin "$RESULTS_JSON" "tests_probe_detection"
JSON_FIRST_RUN=1

append_json() {
  local name="$1" status="$2" duration="$3"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then
    echo "," >> "$RESULTS_JSON"
  fi
  JSON_FIRST_RUN=0
  echo -n "  {\"name\":\"${name}\",\"status\":\"${status}\",\"duration_sec\":${duration}}" >> "$RESULTS_JSON"
}

run_case() {
  local name="$1"
  shift
  local start end duration
  start=$(date +%s)
  echo -e "\n> ${name}" | tee -a "$LOG_FILE"
  echo "  Cmd: $*" | tee -a "$LOG_FILE"
  if run "$@" >>"$LOG_FILE" 2>&1; then
    end=$(date +%s)
    duration=$((end - start))
    append_json "$name" "ok" "$duration"
    info "${name}: pass" | tee -a "$LOG_FILE"
    return 0
  fi
  end=$(date +%s)
  duration=$((end - start))
  append_json "$name" "fail" "$duration"
  error "${name}: fail" | tee -a "$LOG_FILE"
  return 1
}

FAIL=0

if ! run_case "Probe detector invariants" cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture; then
  FAIL=$((FAIL + 1))
fi

if ! run_case "Reality fallback target rotation" cargo test --release --features rust-tests --test rt-reality-targets -- --nocapture; then
  FAIL=$((FAIL + 1))
fi

if ! run_case "Stealth runtime worker lifecycle" cargo test --release --features rust-tests --test rt-stealth-runtime-lifecycle -- --nocapture; then
  FAIL=$((FAIL + 1))
fi

if (( FAST == 0 )); then
  if ! run_case "Stealth core suite (probe pressure paths)" ./scripts/tests/suites/test-stealth.sh --fast; then
    FAIL=$((FAIL + 1))
  fi
fi

if (( SOAK_ITERS > 0 )); then
  i=1
  while (( i <= SOAK_ITERS )); do
    if ! run_case "Probe soak iteration ${i}/${SOAK_ITERS}" cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture; then
      FAIL=$((FAIL + 1))
      break
    fi
    i=$((i + 1))
  done
fi

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  Probe Detection Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
if (( FAIL == 0 )); then
  echo "  [OK] All probe validation checks passed" | tee -a "$LOG_FILE"
else
  echo "  [FAIL] Probe validation failures: ${FAIL}" | tee -a "$LOG_FILE"
fi
echo "  Artifacts: ${OUTPUT_DIR}" | tee -a "$LOG_FILE"

exit $(( FAIL > 0 ))
