#!/usr/bin/env bash
# Description: Micro-benchmark runner: micro-crypto-all.
set -euo pipefail

# Microbench Suite (Crypto): AES block, GHASH, AES-GCM, ChaCha x4
# Consistent with existing scripts: uses scripts/tests/lib/lib-common.sh, scripts/out paths, flags

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

# Defaults
ITERS=500
SIZES=(256B 1KiB 16KiB 1MiB)
OUTPUT_DIR=""
DRY_RUN=""
RUSTFLAGS_EXTRA=""
CARGO_FEATURES="benches"
JOBS=""
FAST=0

# Flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iters) ITERS="$2"; shift;;
    --sizes) shift; SIZES=( ); while [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]]; do SIZES+=("$1"); shift; done; continue;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --features) CARGO_FEATURES="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--iters N] [--sizes <list>]"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

if [[ "$FAST" -eq 1 ]]; then
  SIZES=(256B 16KiB)
  ITERS=200
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$ARTIFACTS_DIR/results.json"; json_begin "$RESULTS_JSON" "$BASE_NAME"; JSON_FIRST_RUN=1
OUT_CSV="$ARTIFACTS_DIR/microbench.csv"

append_item() {
  local cell="$1"; local result="$2"; local reason="$3"; local command_status="$4"; local output_file="$5"
  local command_text="${6:-}"; local environment="${7:-}"
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  printf '  {"cell":"%s","result":"%s","reason":"%s","command":"%s","environment":"%s","command_status":%s,"output":"%s"}' \
    "$(qf_json_escape "$cell")" "$(qf_json_escape "$result")" "$(qf_json_escape "$reason")" \
    "$(qf_json_escape "$command_text")" "$(qf_json_escape "$environment")" "$command_status" \
    "$(qf_json_escape "$output_file")" >> "$RESULTS_JSON"
}

size_to_bytes() {
  local value="$1"; local base; local numeric
  case "$value" in
    *[kK][iI][bB])
      base="${value:0:${#value}-3}"
      [[ "$base" =~ ^[0-9]+$ ]] || return 2
      numeric=$((10#$base))
      (( numeric > 0 && numeric <= 65536 )) || return 2
      printf '%s\n' "$((numeric * 1024))"
      ;;
    *[mM][iI][bB])
      base="${value:0:${#value}-3}"
      [[ "$base" =~ ^[0-9]+$ ]] || return 2
      numeric=$((10#$base))
      (( numeric > 0 && numeric <= 64 )) || return 2
      printf '%s\n' "$((numeric * 1024 * 1024))"
      ;;
    *[bB])
      base="${value:0:${#value}-1}"
      [[ "$base" =~ ^[0-9]+$ ]] || return 2
      numeric=$((10#$base))
      (( numeric > 0 && numeric <= 67108864 )) || return 2
      printf '%s\n' "$numeric"
      ;;
    *) return 2;;
  esac
}

print_system_banner

input_ok=1
validate_positive_int "iteration count" "$ITERS" 10000000 || input_ok=0
validate_feature_list "cargo features" "$CARGO_FEATURES" || input_ok=0
validate_control_free_value "RUSTFLAGS_EXTRA" "$RUSTFLAGS_EXTRA" 8192 || input_ok=0
if [[ -n "$JOBS" ]]; then
  validate_positive_int "jobs" "$JOBS" 64 || input_ok=0
fi
if [[ "${#SIZES[@]}" -eq 0 ]]; then
  input_ok=0
fi
for size in "${SIZES[@]}"; do
  if ! size_to_bytes "$size" >/dev/null; then
    input_ok=0
  fi
done
if [[ "$input_ok" -ne 1 ]]; then
  append_item "input" "FAIL" "invalid_cli_input_or_size" 2 ""
  json_end "$RESULTS_JSON"
  exit 2
fi

info "Microbench sizes: ${SIZES[*]} | iters=$ITERS"
if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
JSON_FIRST_RUN=0
printf '  {"cell":"meta","result":"PASS","reason":"","command":"","environment":"","command_status":0,"meta":{"iters":%s,"sizes":"%s","fast":%s}}' \
  "$ITERS" "$(qf_json_escape "${SIZES[*]}")" "$FAST" >> "$RESULTS_JSON"

echo "ts,$(date -Iseconds)" | tee "$OUT_CSV" >/dev/null

microbench_run() {
  local kind="$1"; shift
  local envs=( )
  [[ -n "$RUSTFLAGS_EXTRA" ]] && envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}")
  local cmd=(cargo run --release -q)
  [[ -n "$CARGO_FEATURES" ]] && cmd+=(--features "$CARGO_FEATURES")
  [[ -n "$JOBS" ]] && cmd+=(-j "$JOBS")
  cmd+=(--example microbench -- "$kind" "$@")
  if [[ -n "$DRY_RUN" ]]; then
    printf 'DRY-RUN:'; printf ' %q' "${cmd[@]}"; printf '\n'
    return 0
  fi
  run env "${envs[@]}" "${cmd[@]}"
}

microbench_capture() {
  local kind="$1"; shift
  local envs=( )
  [[ -n "$RUSTFLAGS_EXTRA" ]] && envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}")
  local cmd=(cargo run --release -q)
  [[ -n "$CARGO_FEATURES" ]] && cmd+=(--features "$CARGO_FEATURES")
  [[ -n "$JOBS" ]] && cmd+=(-j "$JOBS")
  cmd+=(--example microbench -- "$kind" "$@")
  if [[ -n "$DRY_RUN" ]]; then
    printf 'DRY-RUN'; printf ' %q' "${cmd[@]}"; printf '\n'
    return 0
  fi
  env "${envs[@]}" "${cmd[@]}"
}

FAILURES=0
PROFILE_OUTPUT="$ARTIFACTS_DIR/profile.txt"
profile_status=0
if microbench_capture profile > "$PROFILE_OUTPUT" 2>&1; then
  profile_result="PASS"
  profile_reason=""
else
  profile_status=$?
  profile_result="FAIL"
  profile_reason="profile_command_failed"
  FAILURES=$((FAILURES + 1))
fi
PROFILE_LINE="$(<"$PROFILE_OUTPUT")"
cat "$PROFILE_OUTPUT"
info "CPU profile: $PROFILE_LINE"
echo "$PROFILE_LINE" | tee -a "$OUT_CSV" >/dev/null
append_item "profile" "$profile_result" "$profile_reason" "$profile_status" "$PROFILE_OUTPUT" \
  "cargo run --release -q --example microbench -- profile" "RUSTFLAGS=${RUSTFLAGS_EXTRA}; CARGO_FEATURES=${CARGO_FEATURES}; JOBS=${JOBS}"

microbench_command_text() {
  local kind="$1"; local size="$2"; local iters="$3"
  printf 'cargo run --release -q'
  [[ -n "$CARGO_FEATURES" ]] && printf ' --features %q' "$CARGO_FEATURES"
  [[ -n "$JOBS" ]] && printf ' -j %q' "$JOBS"
  printf ' --example microbench -- %q %q %q' "$kind" "$size" "$iters"
}

run_microbench_cell() {
  local kind="$1"; local size="$2"; local iters="$3"; local cell="$4"
  local output_file="$ARTIFACTS_DIR/cell-${cell}.txt"
  local cell_status=0; local cell_result="PASS"; local cell_reason=""
  if microbench_run "$kind" "$size" "$iters" > "$output_file" 2>&1; then
    cell_status=0
  else
    cell_status=$?
    cell_result="FAIL"
    cell_reason="microbench_command_failed"
    FAILURES=$((FAILURES + 1))
  fi
  cat "$output_file"
  cat "$output_file" >> "$OUT_CSV"
  append_item "${kind}:${size}" "$cell_result" "$cell_reason" "$cell_status" "$output_file" \
    "$(microbench_command_text "$kind" "$size" "$iters")" \
    "RUSTFLAGS=${RUSTFLAGS_EXTRA}; CARGO_FEATURES=${CARGO_FEATURES}; JOBS=${JOBS}"
}

CELL=0
for sz in "${SIZES[@]}"; do
  info "Running microbenches for size=$sz, iters=$ITERS"
  for kind in aes-block ghash aes-gcm chacha-x4 morus-enc morus-dec poly1305-mac sha256 hmac-sha256; do
    CELL=$((CELL + 1))
    run_microbench_cell "$kind" "$sz" "$ITERS" "$CELL"
  done
  echo "---" | tee -a "$OUT_CSV"
done

json_end "$RESULTS_JSON"
info "Results saved to: $ARTIFACTS_DIR"
if [[ "$FAILURES" -gt 0 ]]; then
  exit 1
fi
