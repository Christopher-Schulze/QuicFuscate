#!/usr/bin/env bash
# Description: Analyze suite execution matrix and fast-flag compatibility.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help|help)
      cat <<'EOF'
Usage: analysis-suite-matrix.sh [--output-dir DIR]

Produces a suite matrix report:
- all scripts/tests/suites/*.sh
- whether each supports --fast
- whether util-run-full-suite invokes it
- whether util-run-full-suite passes --fast to it

Writes report.txt and results.json.
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUT_DIR" ]] && OUT_DIR="$PROJECT_ROOT/scripts/out/analysis/suite-matrix-$TS"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.txt"
JSON="$OUT_DIR/results.json"
FULL_SUITE="$PROJECT_ROOT/scripts/tests/utils/util-run-full-suite.sh"
json_begin "$JSON" "analysis_suite_matrix"
JSON_FIRST_RUN=1

total=0
fast_supported=0
invoked=0
invoked_with_fast=0
mismatch_fast=0

{
  echo "Suite Matrix Report ($TS)"
  echo "Full suite runner: ${FULL_SUITE#$PROJECT_ROOT/}"
  echo
} > "$REPORT"

for f in "$PROJECT_ROOT"/scripts/tests/suites/*.sh; do
  [[ -f "$f" ]] || continue
  total=$((total + 1))
  rel="${f#$PROJECT_ROOT/}"
  name="$(basename "$f")"

  supports_fast=0
  if grep -q -- "--fast" "$f"; then
    supports_fast=1
    fast_supported=$((fast_supported + 1))
  fi

  call_count="$(grep -cF "$name" "$FULL_SUITE" || true)"
  if [[ "$call_count" -gt 0 ]]; then
    invoked=$((invoked + 1))
  fi

  call_with_fast=0
  if grep -nF "$name" "$FULL_SUITE" | grep -q -- "--fast"; then
    call_with_fast=1
    invoked_with_fast=$((invoked_with_fast + 1))
  fi

  mismatch=0
  if [[ "$call_with_fast" -eq 1 && "$supports_fast" -eq 0 ]]; then
    mismatch=1
    mismatch_fast=$((mismatch_fast + 1))
    echo "MISMATCH_FAST_FLAG $rel" >> "$REPORT"
  fi

  printf "%s supports_fast=%s invoked=%s invoked_with_fast=%s\n" \
    "$rel" "$supports_fast" "$([[ "$call_count" -gt 0 ]] && echo 1 || echo 0)" "$call_with_fast" >> "$REPORT"

  invoked_flag=0
  [[ "$call_count" -gt 0 ]] && invoked_flag=1
  qf_json_append_object "$JSON" \
    "suite=$rel" "supports_fast=int:$supports_fast" "invoked=int:$invoked_flag" \
    "invoked_with_fast=int:$call_with_fast" "fast_flag_mismatch=int:$mismatch"
done

json_end "$JSON"

cat >> "$REPORT" <<EOF

Summary:
  total=$total
  fast_supported=$fast_supported
  invoked_by_full_suite=$invoked
  invoked_with_fast_flag=$invoked_with_fast
  fast_flag_mismatch=$mismatch_fast
EOF

echo "report: $REPORT"
echo "json:   $JSON"
