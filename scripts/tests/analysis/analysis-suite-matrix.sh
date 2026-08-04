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

total=0
fast_supported=0
invoked=0
invoked_with_fast=0
mismatch_fast=0
excluded=0
unowned_omissions=0

suite_exclusion() {
  case "$1" in
    test-ddos-admission.sh)
      printf '%s\n' 'process-real-security-proof|TODO-688|No executable full-suite or CI invocation in the current snapshot'
      ;;
    test-fec-all.sh)
      printf '%s\n' 'dispatcher|TODO-730|Dispatcher delegates to constituent FEC lanes already invoked by the full suite'
      ;;
    test-graceful-shutdown.sh)
      printf '%s\n' 'process-real-lifecycle-proof|TODO-448|Dedicated graceful-shutdown proof owner; no safe default full-suite invocation'
      ;;
    test-linux-installer-guest.sh)
      printf '%s\n' 'indirect-native-lane|TODO-541|Executed by test-linux-installer.sh inside the linux-installer-native CI job'
      ;;
    test-linux-installer.sh)
      printf '%s\n' 'native-ci-lane|TODO-541|Executed by the linux-installer-native CI job in .github/workflows/ci.yml'
      ;;
    test-qkey-auth-policy.sh)
      printf '%s\n' 'process-real-security-proof|TODO-688|Dedicated QKey policy proof; no executable full-suite or CI invocation in the current snapshot'
      ;;
    test-qkey-registry-encryption.sh)
      printf '%s\n' 'process-real-security-proof|TODO-539|Dedicated registry encryption proof; no safe default full-suite invocation'
      ;;
    *) return 1;;
  esac
}

{
  echo "Suite Matrix Report ($TS)"
  echo "Full suite runner: ${FULL_SUITE#"$PROJECT_ROOT"/}"
  echo
} > "$REPORT"

for f in "$PROJECT_ROOT"/scripts/tests/suites/*.sh; do
  [[ -f "$f" ]] || continue
  total=$((total + 1))
  rel="${f#"$PROJECT_ROOT"/}"
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

  exclusion_kind=""
  exclusion_owner=""
  exclusion_reason=""
  suite_result="PASS"
  if [[ "$call_count" -eq 0 ]]; then
    exclusion_record="$(suite_exclusion "$name" || true)"
    if [[ -n "$exclusion_record" ]]; then
      IFS='|' read -r exclusion_kind exclusion_owner exclusion_reason <<< "$exclusion_record"
      excluded=$((excluded + 1))
      echo "EXCLUDED $rel kind=$exclusion_kind owner=$exclusion_owner reason=$exclusion_reason" >> "$REPORT"
    else
      unowned_omissions=$((unowned_omissions + 1))
      suite_result="FAIL"
      echo "UNOWNED_OMISSION $rel" >> "$REPORT"
    fi
  fi

  invoked_flag=0
  [[ "$call_count" -gt 0 ]] && invoked_flag=1
  if [[ -n "$exclusion_owner" ]]; then
    printf "%s supports_fast=%s invoked=%s invoked_with_fast=%s status=EXCLUDED owner=%s lane=%s reason=%s\n" \
      "$rel" "$supports_fast" "$invoked_flag" "$call_with_fast" "$exclusion_owner" "$exclusion_kind" "$exclusion_reason" >> "$REPORT"
  else
    printf "%s supports_fast=%s invoked=%s invoked_with_fast=%s status=%s\n" \
      "$rel" "$supports_fast" "$invoked_flag" "$call_with_fast" "$([[ "$unowned_omissions" -gt 0 && "$call_count" -eq 0 ]] && echo FAIL || echo PASS)" >> "$REPORT"
  fi

  qf_json_append_object "$JSON" \
    "suite=$rel" "supports_fast=int:$supports_fast" "invoked=int:$invoked_flag" \
    "invoked_with_fast=int:$call_with_fast" "fast_flag_mismatch=int:$mismatch" \
    "status=$([[ "$suite_result" == FAIL ]] && echo FAIL || echo PASS)" \
    "result=$([[ -n "$exclusion_owner" ]] && echo EXCLUDED || echo "$suite_result")" \
    "owner=$exclusion_owner" "lane=$exclusion_kind" "reason=$exclusion_reason"
done

matrix_status="PASS"
if [[ "$unowned_omissions" -gt 0 ]]; then
  matrix_status="FAIL"
fi
qf_json_append_object "$JSON" "name=suite_matrix_summary" "status=$matrix_status" \
  "total=int:$total" "invoked=int:$invoked" "excluded=int:$excluded" \
  "unowned_omissions=int:$unowned_omissions" "fast_flag_mismatch=int:$mismatch_fast"
json_end "$JSON"

cat >> "$REPORT" <<EOF

Summary:
  total=$total
  fast_supported=$fast_supported
  invoked_by_full_suite=$invoked
  invoked_with_fast_flag=$invoked_with_fast
  excluded_with_owner=$excluded
  unowned_omissions=$unowned_omissions
  fast_flag_mismatch=$mismatch_fast
EOF

echo "report: $REPORT"
echo "json:   $JSON"

if [[ "$unowned_omissions" -gt 0 ]]; then
  exit 1
fi
