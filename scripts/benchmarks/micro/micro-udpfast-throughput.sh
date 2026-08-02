#!/usr/bin/env bash
# Description: Micro-benchmark runner: micro-udpfast-throughput.
set -euo pipefail

# Microbench: UDP fast-path throughput (loopback by default, optional LAN target)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
SIZE="1200"
ITERS=10000
BATCH=32
BIND="0.0.0.0:0"
REMOTE=""
FAST=0
ITERS_EXPLICIT=0
BATCH_EXPLICIT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --size) SIZE="$2"; shift;;
    --iters) ITERS="$2"; ITERS_EXPLICIT=1; shift;;
    --batch) BATCH="$2"; BATCH_EXPLICIT=1; shift;;
    --bind) BIND="$2"; shift;;
    --remote) REMOTE="$2"; shift;;
    --fast) FAST=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--size N] [--iters N] [--batch N] [--bind IP:PORT] [--remote IP:PORT] [--fast]"
      usage_common_flags 2>/dev/null || true
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$ARTIFACTS_DIR/${BASE_NAME}.json"; JSON="$RESULTS_JSON"; json_begin "$RESULTS_JSON" "$BASE_NAME"; JSON_FIRST_RUN=1

if [[ "$FAST" -eq 1 && "$ITERS_EXPLICIT" -eq 0 ]]; then
  ITERS=2000
fi
if [[ "$FAST" -eq 1 && "$BATCH_EXPLICIT" -eq 0 ]]; then
  BATCH=16
fi

append_item() {
  local cell="$1"; local result="$2"; local reason="$3"; local command_status="$4"; local output_file="$5"
  local command_text="${6:-}"
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  printf '  {"cell":"%s","result":"%s","reason":"%s","command":"%s","command_status":%s,"output":"%s"}' \
    "$(qf_json_escape "$cell")" "$(qf_json_escape "$result")" "$(qf_json_escape "$reason")" \
    "$(qf_json_escape "$command_text")" "$command_status" "$(qf_json_escape "$output_file")" >> "$RESULTS_JSON"
}

validate_endpoint() {
  local label="$1"; local value="$2"; local allow_zero="$3"
  validate_control_free_value "$label" "$value" 256 || return 2
  local host=""; local port=""
  if [[ "$value" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  elif [[ "$value" =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    error "${label} must be host:port or [ipv6]:port"
    return 2
  fi
  [[ -n "$host" ]] || { error "${label} host must not be empty"; return 2; }
  validate_nonnegative_int "${label} port" "$port" 65535 || return 2
  if [[ "$allow_zero" != "1" && "$port" == "0" ]]; then
    error "${label} port must be greater than zero"
    return 2
  fi
}

input_ok=1
validate_positive_int "UDP packet size" "$SIZE" 65507 || input_ok=0
validate_positive_int "iteration count" "$ITERS" 10000000 || input_ok=0
validate_positive_int "batch size" "$BATCH" 4096 || input_ok=0
validate_endpoint "bind address" "$BIND" 1 || input_ok=0
if [[ -n "$REMOTE" ]]; then
  validate_endpoint "remote address" "$REMOTE" 0 || input_ok=0
fi
if [[ "$input_ok" -ne 1 ]]; then
  append_item "input" "FAIL" "invalid_cli_input" 2 ""
  json_end "$RESULTS_JSON"
  exit 2
fi

print_system_banner
info "UDP fast-path throughput: size=$SIZE bytes iters=$ITERS batch=$BATCH bind=$BIND"
if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
JSON_FIRST_RUN=0
printf '  {"cell":"meta","result":"PASS","reason":"","command":"","command_status":0,"meta":{"size":%s,"iters":%s,"batch":%s,"bind":"%s","remote":"%s"}}' \
  "$SIZE" "$ITERS" "$BATCH" "$(qf_json_escape "$BIND")" "$(qf_json_escape "$REMOTE")" >> "$RESULTS_JSON"

if run_cargo build --release; then
  :
else
  build_status=$?
  append_item "build" "FAIL" "harness_build_failed" "$build_status" "" "cargo build --release"
  json_end "$RESULTS_JSON"
  exit "$build_status"
fi

RESULTS="$ARTIFACTS_DIR/${BASE_NAME}.txt"
if [[ -n "$REMOTE" ]]; then
  info "Running LAN mode (remote=$REMOTE)"
  command=(target/release/harness udp-throughput --size "$SIZE" --iters "$ITERS" --batch "$BATCH" --bind "$BIND" --remote "$REMOTE")
else
  info "Running loopback mode (receiver spawned locally)"
  command=(target/release/harness udp-throughput --size "$SIZE" --iters "$ITERS" --batch "$BATCH" --bind "$BIND")
fi
command_status=0
if run "${command[@]}" > "$RESULTS" 2>&1; then
  result="PASS"
  reason=""
else
  command_status=$?
  result="FAIL"
  reason="harness_command_failed"
fi
cat "$RESULTS"
command_text="$(printf '%q ' "${command[@]}")"
command_text="${command_text% }"
append_item "udp-throughput" "$result" "$reason" "$command_status" "$RESULTS" "$command_text"

json_end "$RESULTS_JSON"
info "Results saved to: $ARTIFACTS_DIR"
if [[ "$result" == "FAIL" ]]; then
  exit 1
fi
