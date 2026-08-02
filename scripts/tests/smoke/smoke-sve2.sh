#!/usr/bin/env bash
# Description: Shell utility script: smoke-sve2.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${PROJECT_ROOT}"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR]"; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

STAMP="$(date +%Y%m%d-%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${STAMP}"
ARTIFACT_DIR="$OUTPUT_DIR"
mkdir -p "${ARTIFACT_DIR}"
JSON="$ARTIFACT_DIR/results.json"; json_begin "$JSON" "tests_smoke_sve2"; JSON_FIRST_RUN=1

if [[ "$(uname -m)" != "aarch64" ]]; then
  warn "host arch is $(uname -m); SVE2 coverage requires aarch64 hardware"
fi

info "collecting feature detector snapshot"
cargo run --quiet --example microbench profile > "${ARTIFACT_DIR}/profile.csv"

run_test() {
  local name=$1
  shift
  info "running ${name}"
  if ! "$@" > "${ARTIFACT_DIR}/${name}.log" 2>&1; then
    error "${name} failed. See ${ARTIFACT_DIR}/${name}.log"
    exit 1
  fi
  qf_json_append_object "$JSON" "test=$name" "log=${ARTIFACT_DIR}/${name}.log"
}

run_test simd-selfcheck run_cargo test --features simd-selfcheck,rust-tests --test rt-simd-selfcheck
run_test telemetry run_cargo test --features rust-tests --test rt-telemetry-counters
run_test sve2-varint run_cargo test --lib test_sve2_varint_roundtrip

json_end "$JSON"
info "all SVE2 smoke tests completed successfully"
