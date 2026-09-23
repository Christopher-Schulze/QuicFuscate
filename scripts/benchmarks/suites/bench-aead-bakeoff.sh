#!/usr/bin/env bash
# Description: Same-API AEAD bakeoff runner (TODO-1038).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
DRY_RUN=0
OWNERS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --dry-run) DRY_RUN=1;;
    --owners) OWNERS="$2"; shift;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--fast|--full] [--dry-run] [--owners LIST]"
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
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/aead-bakeoff-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

if (( FAST )); then
  ITERS=120
  WARMUP=20
  SIZES="64,1024,1400,8192"
else
  ITERS=800
  WARMUP=80
  SIZES="64,256,512,1024,1200,1400,8192"
fi

FEATURES="benches,aead-bakeoff"
if [[ "${QF_BAKEOFF_AWS_LC:-1}" == "1" ]]; then
  FEATURES="${FEATURES},rustls-aws-lc"
fi

HOST_FILE="$OUTPUT_DIR/host.txt"
MATRIX_FILE="$OUTPUT_DIR/matrix.txt"
VECTORS_FILE="$OUTPUT_DIR/vectors.txt"
MATCH_FILE="$OUTPUT_DIR/x-match.txt"
DISTINGUISH_FILE="$OUTPUT_DIR/distinguish.txt"
PROFILE_FILE="$OUTPUT_DIR/profile.txt"
CPU_FILE="$OUTPUT_DIR/cpu.txt"
COMMAND_FILE="$OUTPUT_DIR/command.txt"

{
  echo "host=$(hostname)"
  echo "os=$(uname -s)"
  echo "arch=$(uname -m)"
  echo "cpu=$(cpu_name)"
  echo "cores=$(cpu_cores)"
  echo "rustc=$(rustc --version)"
  echo "commit=$(git rev-parse HEAD)"
  echo "features=$FEATURES"
  echo "iters=$ITERS"
  echo "warmup=$WARMUP"
  echo "sizes=$SIZES"
} > "$HOST_FILE"
cp "$HOST_FILE" "$CPU_FILE"

COMMON_ARGS=(--sizes "$SIZES" --iters "$ITERS" --warmup "$WARMUP" --out "$OUTPUT_DIR")
if [[ -n "$OWNERS" ]]; then
  COMMON_ARGS+=(--owners "$OWNERS")
fi

CARGO_CMD=(cargo run --release --example aead_bakeoff --features "$FEATURES" --quiet --)
{
  echo "command=${CARGO_CMD[*]} ${COMMON_ARGS[*]}"
  echo "features=$FEATURES"
} > "$COMMAND_FILE"

if (( DRY_RUN )); then
  echo "DRY-RUN: ${CARGO_CMD[*]} ${COMMON_ARGS[*]}"
  echo "output_dir=$OUTPUT_DIR"
  exit 0
fi

free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
if ! [[ "$free_kib" =~ ^[0-9]+$ ]] || (( free_kib < 2 * 1024 * 1024 )); then
  echo "FAIL: at least 2 GiB of free disk space is required before the bakeoff." >&2
  exit 1
fi

run_mode() {
  local label="$1"
  local out_file="$2"
  shift 2
  echo "=== $label ==="
  if "${CARGO_CMD[@]}" "$@" >"$out_file" 2>"$OUTPUT_DIR/${label}.err"; then
    cat "$out_file"
    return 0
  fi
  echo "[FAIL] $label" >&2
  cat "$OUTPUT_DIR/${label}.err" >&2
  return 1
}

FAILURES=0
run_mode vectors "$VECTORS_FILE" --vectors || FAILURES=$((FAILURES + 1))
run_mode x-match "$MATCH_FILE" --match-x || FAILURES=$((FAILURES + 1))
run_mode matrix "$MATRIX_FILE" "${COMMON_ARGS[@]}" || FAILURES=$((FAILURES + 1))
run_mode distinguish "$DISTINGUISH_FILE" --distinguish --iters "$ITERS" || FAILURES=$((FAILURES + 1))
run_mode profile "$PROFILE_FILE" --profile --sizes 1400 --iters "$ITERS" --warmup "$WARMUP" || FAILURES=$((FAILURES + 1))

echo "output_dir=$OUTPUT_DIR"
if [[ "$FAILURES" -gt 0 ]]; then
  echo "FAIL: $FAILURES bakeoff modes failed"
  exit 1
fi
echo "PASS: aead bakeoff"
