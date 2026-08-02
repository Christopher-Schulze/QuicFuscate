#!/usr/bin/env bash
# Description: Micro-benchmark runner: micro-aes-gcm.
set -euo pipefail

# Microbench: AES-GCM seal (encrypt + tag)
# Uses examples/microbench.rs as driver. Consistent with repo conventions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

# Defaults
ITERS=500
SIZES=(256B 1KiB 16KiB 1MiB)
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iters) ITERS="$2"; shift;;
    --sizes) shift; SIZES=( ); while [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]]; do SIZES+=("$1"); shift; done; continue;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--iters N] [--sizes <list>]"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
OUT_CSV="$ARTIFACTS_DIR/${BASE_NAME}.csv"
RESULTS_JSON="$ARTIFACTS_DIR/${BASE_NAME}.json"; JSON="$RESULTS_JSON"; json_begin "$RESULTS_JSON" "$BASE_NAME"; JSON_FIRST_RUN=1

print_system_banner
info "AES-GCM microbench sizes: ${SIZES[*]} | iters=$ITERS"
qf_json_append_object "$RESULTS_JSON" "cell=meta" "result=PASS" "reason=" \
  "argv=json:[]" "environment=json:$(qf_json_environment)" "command_status=int:0" \
  "meta=json:{\"iters\":$ITERS,\"sizes\":\"$(qf_json_escape "${SIZES[*]}")\"}"

echo "ts,$(date -Iseconds)" | tee "$OUT_CSV" >/dev/null

for sz in "${SIZES[@]}"; do
  run cargo run --release -q --example microbench -- aes-gcm "$sz" "$ITERS" | tee -a "$OUT_CSV"
  echo "---" | tee -a "$OUT_CSV"
done

json_end "$RESULTS_JSON"
info "Results saved to: $ARTIFACTS_DIR"
