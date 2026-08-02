#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-orchestrator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
DRY_RUN=0
SUITE_FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --suite) SUITE_FILTER="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --list) LIST_ONLY=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "Benchmark Orchestrator Suite"; usage_common_flags 2>/dev/null || true;
      echo "  --suite list     Comma-separated suite list (e.g., crypto,fec,transport)";
      echo "  --list           Print available suites";
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
 done

SUITE_NAMES=()
if (( FAST )); then
  SUITE_NAMES+=(micro-crypto-all fec-simulation-fast transport stealth)
else
  SUITE_NAMES+=(crypto fec transport compression optimization stealth stealth-brain qpack-encode)
fi

if [[ -n "${LIST_ONLY:-}" ]]; then
  echo "Available suites:"
  for name in "${SUITE_NAMES[@]}"; do
    echo "  - ${name}"
  done
  exit 0
fi

if [[ -n "$SUITE_FILTER" ]]; then
  IFS=',' read -r -a requested <<< "$SUITE_FILTER"
  FILTERED=()
  for want in "${requested[@]}"; do
    found=0
    for name in "${SUITE_NAMES[@]}"; do
      if [[ "$name" == "$want" ]]; then
        FILTERED+=("$name")
        found=1
        break
      fi
    done
    if [[ "$found" -eq 0 ]]; then
      error "Unknown benchmark suite requested: ${want}"
      exit 2
    fi
  done
  SUITE_NAMES=("${FILTERED[@]}")
fi

if [[ ${#SUITE_NAMES[@]} -eq 0 ]]; then
  echo "No suites selected; exiting."
  exit 0
fi

RUN_TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/bench-orchestrator-${RUN_TS}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
mkdir -p "$OUTPUT_DIR"
COMMANDS_FILE="$OUTPUT_DIR/commands.txt"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
MANIFEST="$OUTPUT_DIR/manifest.json"

json_begin "$MANIFEST" "bench_orchestrator"
JSON_FIRST_RUN=1

append_item() {
  local name="$1"; local result="$2"; local reason="$3"
  local command_status="$4"; local dur="$5"; local log="$6"
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then
    echo "," >> "$MANIFEST"
  fi
  JSON_FIRST_RUN=0
  local command_text; command_text=$(printf '%q ' "${SUITE_ARGV[@]}")
  command_text="${command_text% }"
  printf '  {"name":"%s","result":"%s","reason":"%s","argv":[' \
    "$(qf_json_escape "$name")" "$(qf_json_escape "$result")" "$(qf_json_escape "$reason")" >> "$MANIFEST"
  local index=0; local arg
  for arg in "${SUITE_ARGV[@]}"; do
    [[ "$index" -eq 0 ]] || printf ',' >> "$MANIFEST"
    printf '"%s"' "$(qf_json_escape "$arg")" >> "$MANIFEST"
    index=$((index + 1))
  done
  printf '],"command":"%s","command_status":%s,"duration_sec":%s,"log":"%s"}' \
    "$(qf_json_escape "$command_text")" "$command_status" "$dur" "$(qf_json_escape "$log")" >> "$MANIFEST"
}

print_system_banner
log "writing artifacts to ${OUTPUT_DIR}"

: > "$SUMMARY_FILE"

FAILED_SUITES=0
for name in "${SUITE_NAMES[@]}"; do
  suite_script=""
  suite_args=()
  case "$name" in
    micro-crypto-all) suite_script="$SCRIPT_DIR/../micro/micro-crypto-all.sh"; suite_args=(--fast);;
    fec-simulation-fast) suite_script="$SCRIPT_DIR/bench-fec-simulation.sh"; suite_args=(--fast);;
    crypto) suite_script="$SCRIPT_DIR/bench-crypto.sh";;
    fec) suite_script="$SCRIPT_DIR/bench-fec.sh";;
    transport) suite_script="$SCRIPT_DIR/bench-transport.sh"; [[ "$FAST" -eq 1 ]] && suite_args=(--fast);;
    compression) suite_script="$SCRIPT_DIR/bench-compression.sh";;
    optimization) suite_script="$SCRIPT_DIR/bench-optimization.sh";;
    stealth) suite_script="$SCRIPT_DIR/bench-stealth.sh"; [[ "$FAST" -eq 1 ]] && suite_args=(--fast);;
    stealth-brain) suite_script="$SCRIPT_DIR/bench-stealth-brain.sh";;
    qpack-encode) suite_script="$SCRIPT_DIR/bench-qpack-encode.sh";;
    *) error "Unknown benchmark suite: ${name}"; FAILED_SUITES=$((FAILED_SUITES + 1)); continue;;
  esac
  suite_dir="$OUTPUT_DIR/${name}"
  mkdir -p "$suite_dir"
  SUITE_ARGV=("$suite_script" "${suite_args[@]}" --output-dir "$suite_dir")
  printf '%q ' "${SUITE_ARGV[@]}" | sed 's/[[:space:]]$//' >> "$COMMANDS_FILE"
  printf '\n' >> "$COMMANDS_FILE"

  log "running suite: ${name}"
  start_ts=$(date +%s)
  if (( DRY_RUN )); then
    echo "DRY-RUN: $(printf '%q ' "${SUITE_ARGV[@]}")"
    result="SKIP"
    reason="dry_run"
    command_status="null"
  else
    if "${SUITE_ARGV[@]}" > "$suite_dir/${name}.log" 2>&1; then
      command_status=0
      result="PASS"
      reason=""
    else
      command_status=$?
      result="FAIL"
      reason="suite_command_failed"
      FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
  fi
  end_ts=$(date +%s)
  duration=$(( end_ts - start_ts ))
  append_item "$name" "$result" "$reason" "$command_status" "$duration" "$suite_dir/${name}.log"
  printf '%s result=%s status=%s duration=%ss\n' "$name" "$result" "$command_status" "$duration" >> "$SUMMARY_FILE"
  if [[ "$result" == "FAIL" ]]; then
    warn "suite ${name} exited with status=${command_status}"
  else
    info "suite ${name} result=${result}"
  fi
 done

json_end "$MANIFEST"

log "benchmark orchestrator finished"
if [[ "$FAILED_SUITES" -gt 0 ]]; then
  exit 1
fi
