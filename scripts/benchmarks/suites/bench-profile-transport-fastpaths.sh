#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-profile-transport-fastpaths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
JOBS=""
CARGO_FEATURES=""
RUSTFLAGS_EXTRA=""
DRY_RUN=""

usage() {
  cat <<USAGE
Transport fast-path profiling harness

Runs transport benchmarks for baseline (Tokio) and io_uring fast path (Linux only).

Usage: $(basename "$0") [options]

Options:
  --output-dir DIR     Target directory for artifacts (default: scripts/out/benchmarks/<ts>)
  --jobs N             Cargo parallel jobs
  --features STR       Feature list for baseline run (space or comma separated)
  --rustflags STR      Extra RUSTFLAGS (e.g., -C target-cpu=native)
  --fast               Pass through to underlying benchmark script (reduced workload)
  --dry-run            Show commands without executing
  --verbose            Enable QUICFUSCATE_DEBUG_SCRIPTS
  --help, -h           Show this help and exit
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown flag: $1" >&2; usage; exit 2;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="profile-transport-fastpaths"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "bench_transport_fastpaths"; JSON_FIRST_RUN=1
FAILURES=0

echo "==============================================================="
echo "  Transport Fast-Path Profiling"
echo "==============================================================="

run_profile() {
  local mode="$1"
  local feature_str="$2"
  local subdir="$OUTPUT_DIR/$mode"
  mkdir -p "$subdir"
  local args=("--output-dir" "$subdir")
  [[ -n "$JOBS" ]] && args+=("--jobs" "$JOBS")
  [[ -n "$feature_str" ]] && args+=("--features" "$feature_str")
  [[ -n "$RUSTFLAGS_EXTRA" ]] && args+=("--rustflags" "$RUSTFLAGS_EXTRA")
  (( FAST )) && args+=("--fast")
  [[ -n "$DRY_RUN" ]] && args+=("--dry-run")

  local banner="> Profiling ${mode}"
  info "$banner"
  if [[ -n "$DRY_RUN" ]]; then
    echo "DRY-RUN: $SCRIPT_DIR/bench-transport.sh ${args[*]}"
    qf_benchmark_record "$RESULTS_JSON" "transport/${mode}" "not_measured" null "SKIP" "dry_run" 0 \
      "bench-transport" "${feature_str:-benches}" "" \
      "$(qf_json_array "$SCRIPT_DIR/bench-transport.sh" "${args[@]}")" "$(qf_json_environment)"
    return 0
  fi
  local output_file="$subdir/bench-transport.log"
  local command_status=0
  if qf_benchmark_run "$output_file" run "$SCRIPT_DIR/bench-transport.sh" "${args[@]}"; then
    command_status=0
    result="PASS"
    reason=""
  else
    command_status="$QF_BENCH_COMMAND_STATUS"
    result="FAIL"
    reason="profile_command_failed"
    FAILURES=$((FAILURES + 1))
  fi
  qf_benchmark_record "$RESULTS_JSON" "transport/${mode}" "duration_sec" "int:$QF_BENCH_DURATION_SEC" \
    "$result" "$reason" "$command_status" "bench-transport" "${feature_str:-benches}" "$output_file" \
    "$(qf_json_array "$SCRIPT_DIR/bench-transport.sh" "${args[@]}")" "$(qf_json_environment)"
  cat "$output_file"
}

# Baseline Tokio run
BASELINE_FEATURES="$CARGO_FEATURES"
run_profile "tokio" "$BASELINE_FEATURES"

# io_uring run (Linux only)
if [[ "$(detect_os)" == linux ]]; then
  URING_FEATURES="${CARGO_FEATURES}"; [[ -n "$URING_FEATURES" ]] && URING_FEATURES+=" "
  URING_FEATURES+="io_uring"
  if [[ -n "$DRY_RUN" ]]; then
    echo "io_uring features resolved to: $URING_FEATURES"
  fi
  run_profile "io_uring" "$URING_FEATURES"
else
  warn "io_uring profiling skipped (requires Linux host)."
  qf_benchmark_record "$RESULTS_JSON" "transport/io_uring" "not_measured" null "SKIP" \
    "platform_requires_linux" 0 "bench-transport" "io_uring" "" \
    "$(qf_json_array "$SCRIPT_DIR/bench-transport.sh" --features "${CARGO_FEATURES:+$CARGO_FEATURES }io_uring")" "$(qf_json_environment)"
fi

info "Artifacts stored under $OUTPUT_DIR"
json_end "$RESULTS_JSON"
if [[ "$FAILURES" -gt 0 ]]; then
  exit 1
fi
