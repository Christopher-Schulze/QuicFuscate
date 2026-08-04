#!/usr/bin/env bash
# Description: Release readiness gate runner (clippy + audit + deny + geiger).
# shellcheck source=scripts/tests/lib/lib-common.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
SCRIPT_NAME="$(basename "$0" .sh)"

[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
# Readiness commands retain their own status records; avoid duplicate ERR-trap noise.
trap - ERR
OUTPUT_DIR=""
STRICT_GEIGER=0

usage() {
  cat <<'USAGE'
Usage: audit-readiness-gates.sh [--output-dir DIR] [--strict-geiger]

Runs a deterministic readiness gate:
  1) cargo clippy --all-targets --all-features -- -D warnings
  2) cargo audit --json
  3) cargo deny check
  4) cargo geiger --package quicfuscate --all-targets --all-features --forbid-only --output-format Json

Options:
  --output-dir DIR      Output directory (default: scripts/out/audits/readiness-<timestamp>)
  --strict-geiger       Fail if geiger reports unsafe in any checked scope
  -h, --help            Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2;;
    --strict-geiger) STRICT_GEIGER=1; shift;;
    -h|--help|help) usage; exit 0;;
    *) echo "Unknown flag: $1" >&2; usage; exit 2;;
  esac
done

TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/$SCRIPT_NAME-$TS"
mkdir -p "$OUTPUT_DIR"

LOG_DIR="$OUTPUT_DIR/logs"
mkdir -p "$LOG_DIR"
CLIPPY_LOG="$LOG_DIR/cargo-clippy.log"
AUDIT_LOG="$LOG_DIR/cargo-audit.log"
AUDIT_JSON="$LOG_DIR/cargo-audit.json"
DENY_LOG="$LOG_DIR/cargo-deny.log"
GEIGER_JSON="$LOG_DIR/cargo-geiger.json"
GEIGER_LOG="$LOG_DIR/cargo-geiger.log"
SUMMARY="$OUTPUT_DIR/summary.txt"
READINESS_JSON="$OUTPUT_DIR/results.json"

touch "$SUMMARY"
json_begin "$READINESS_JSON" "audit_readiness_gates"

TOTAL_CHECKS=0
FAILED_CHECKS=0
UNAVAILABLE_CHECKS=0
GEIGER_UNSAFE_DEPS=0
GEIGER_UNSAFE_PACKAGES_JSON='[]'

readiness_record() {
  local check="$1" status="$2" details="$3"
  qf_json_append_object "$READINESS_JSON" \
    "name=$check" "status=$status" "evidence=$details"
}

logkpi() {
  local check="$1"
  local status="$2"
  local details="$3"
  if [[ "$status" == "PASS" ]]; then
    echo "[PASS] $check: $details"
  elif [[ "$status" == "WARN" ]]; then
    echo "[WARN] $check: $details"
  else
    echo "[FAIL] $check: $details"
  fi
  printf '%s\t%s\t%s\n' "$check" "$status" "$details" >> "$SUMMARY"
  case "$status" in
    PASS) readiness_record "$check" PASS "$details";;
    WARN)
      ((UNAVAILABLE_CHECKS += 1))
      readiness_record "$check" UNAVAILABLE "$details";;
    FAIL) readiness_record "$check" FAIL "$details";;
  esac
}

run_success_or_fail() {
  local check="$1"; local log_path="$2"
  shift 2
  set +e
  "$@" > "$log_path" 2>&1
  local rc=$?
  set -e
  ((TOTAL_CHECKS += 1))
  if [[ $rc -eq 0 ]]; then
    logkpi "$check" "PASS" "command returned 0"
    return 0
  fi
  ((FAILED_CHECKS += 1))
  logkpi "$check" "FAIL" "command returned rc=$rc"
  return "$rc"
}

advisory_database_unavailable() {
  local log_path="$1"
  grep -Eqi 'advisory database|failed to prepare fetch|couldn.t fetch|IO error|network' "$log_path"
}

echo "==============================================================="
echo "  Quicfuscate upload-readiness gate"
echo "  Output: $OUTPUT_DIR"
echo "==============================================================="

{
  echo "---------------------------------------------------------------"
  echo "RUN START"
  date
  echo "Project root: $PROJECT_ROOT"
  echo "---------------------------------------------------------------"
} > "$SUMMARY"

for required_command in cargo cargo-audit cargo-deny cargo-geiger jq; do
  ((TOTAL_CHECKS += 1))
  if command -v "$required_command" >/dev/null 2>&1; then
    logkpi "preflight:$required_command" "PASS" "command available"
  else
    logkpi "preflight:$required_command" "WARN" "command unavailable"
  fi
done
if [[ "$UNAVAILABLE_CHECKS" -gt 0 ]]; then
  qf_json_append_object "$READINESS_JSON" \
    "name=readiness_summary" "status=UNAVAILABLE" \
    "geiger_policy=$([[ "$STRICT_GEIGER" -eq 1 ]] && echo strict || echo deny-only)" \
    "geiger_dependency_unsafe_count=int:$GEIGER_UNSAFE_DEPS" \
    "geiger_dependency_unsafe_packages=json:$GEIGER_UNSAFE_PACKAGES_JSON" \
    "total_checks=int:$TOTAL_CHECKS" "failed_checks=int:$FAILED_CHECKS" \
    "unavailable_checks=int:$UNAVAILABLE_CHECKS"
  json_end "$READINESS_JSON"
  cat "$SUMMARY"
  exit 1
fi

# 1) Clippy strict
echo "[RUN] cargo clippy strict"
run_success_or_fail "ClippyStrict" "$CLIPPY_LOG" cargo clippy --all-targets --all-features -- -D warnings || true

# 2) cargo audit JSON
echo "[RUN] cargo audit JSON"
set +e
cargo audit --json > "$AUDIT_JSON" 2> "$AUDIT_LOG"
AUDIT_RC=$?
set -e
((TOTAL_CHECKS += 1))
if [[ $AUDIT_RC -ne 0 ]]; then
  if advisory_database_unavailable "$AUDIT_LOG"; then
    logkpi "CargoAudit" "WARN" "advisory database unavailable; command rc=$AUDIT_RC"
  else
    ((FAILED_CHECKS += 1))
    logkpi "CargoAudit" "FAIL" "audit command returned rc=$AUDIT_RC"
  fi
else
  if ! jq -e . "$AUDIT_JSON" >/dev/null 2>&1; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoAudit" "FAIL" "invalid audit JSON output"
  else
    AUDIT_VULN_FOUND="$(jq -r '.vulnerabilities.found // false' "$AUDIT_JSON")"
    AUDIT_VULN_COUNT="$(jq -r '.vulnerabilities.count // 0' "$AUDIT_JSON")"
    AUDIT_WARNING_IDS="$(jq -r '[
      (.warnings.unmaintained // []),
      (.warnings.unsound // []),
      (.warnings.notice // []),
      (.warnings.yanked // [])
    ] | add | map(.advisory.id) | unique | sort | join(", ")' "$AUDIT_JSON")"
    AUDIT_WARNING_COUNT="$(jq -r '[
      (.warnings.unmaintained // []),
      (.warnings.unsound // []),
      (.warnings.notice // []),
      (.warnings.yanked // [])
    ] | add | length' "$AUDIT_JSON")"
    if [[ "$AUDIT_VULN_FOUND" == "true" || "$AUDIT_VULN_COUNT" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoAudit" "FAIL" "vulnerabilities found: count=$AUDIT_VULN_COUNT (found=$AUDIT_VULN_FOUND)"
    elif [[ "$AUDIT_WARNING_COUNT" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoAudit" "FAIL" "informational warnings found: count=$AUDIT_WARNING_COUNT, ids=$AUDIT_WARNING_IDS"
    else
      logkpi "CargoAudit" "PASS" "no vulnerabilities or warnings"
    fi
  fi
fi
cat "$AUDIT_JSON" >> "$AUDIT_LOG"

# 3) deny
echo "[RUN] cargo deny check"
set +e
cargo deny check > "$DENY_LOG" 2>&1
DENY_RC=$?
set -e
((TOTAL_CHECKS += 1))
if [[ $DENY_RC -eq 0 ]]; then
  logkpi "CargoDeny" "PASS" "command returned 0"
elif advisory_database_unavailable "$DENY_LOG"; then
  logkpi "CargoDeny" "WARN" "advisory database unavailable; command rc=$DENY_RC"
else
  ((FAILED_CHECKS += 1))
  logkpi "CargoDeny" "FAIL" "command returned rc=$DENY_RC"
fi

# 4) geiger deterministic
echo "[RUN] cargo geiger strict"
set +e
cargo geiger --package quicfuscate --all-features --all-targets --forbid-only --output-format Json > "$GEIGER_JSON" 2>> "$GEIGER_LOG"
GEIGER_RC=$?
set -e
((TOTAL_CHECKS += 1))
if [[ $GEIGER_RC -ne 0 ]]; then
  if [[ $STRICT_GEIGER -eq 1 ]]; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoGeiger" "FAIL" "command failed rc=$GEIGER_RC"
  else
    logkpi "CargoGeiger" "WARN" "command failed rc=$GEIGER_RC (non-blocking without --strict-geiger)"
  fi
else
  if ! jq -e . "$GEIGER_JSON" >/dev/null 2>&1; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoGeiger" "FAIL" "invalid geiger JSON output"
  else
    GEIGER_ROOT_UNSAFE="$(jq -r '[.packages[] | select(.package.id.name == "quicfuscate")] | first | .forbids_unsafe // false' "$GEIGER_JSON")"
    GEIGER_UNSAFE_DEPS="$(jq -r '[.packages[] | select(.forbids_unsafe and .package.id.name != "quicfuscate")] | length' "$GEIGER_JSON")"
    GEIGER_UNSAFE_PACKAGES_JSON="$(jq -c '[.packages[] | select(.forbids_unsafe and .package.id.name != "quicfuscate") | .package.id.name] | unique | sort' "$GEIGER_JSON" || printf '%s' '[]')"
    if [[ "$GEIGER_ROOT_UNSAFE" == "true" ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoGeiger" "FAIL" "root crate allows unsafe-by-design"
    elif [[ "$STRICT_GEIGER" -eq 1 && "$GEIGER_UNSAFE_DEPS" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoGeiger" "FAIL" "strict mode blocked: dependency unsafe count=$GEIGER_UNSAFE_DEPS"
    else
      logkpi "CargoGeiger" "PASS" "root crate has no unsafe-invoking API in deny-only mode; dependency unsafe count=$GEIGER_UNSAFE_DEPS"
    fi
  fi
fi
cat "$GEIGER_JSON" >> "$GEIGER_LOG"

{
  echo "---------------------------------------------------------------"
  echo "RUN END"
  date
  echo "Total checks: $TOTAL_CHECKS"
  echo "Failed: $FAILED_CHECKS"
  echo "Unavailable: $UNAVAILABLE_CHECKS"
  if [[ "$STRICT_GEIGER" -eq 1 ]]; then
    echo "Geiger policy: strict"
  else
    echo "Geiger policy: deny-only"
  fi
  echo "Geiger dependency unsafe count: $GEIGER_UNSAFE_DEPS"
  if [[ "$FAILED_CHECKS" -ne 0 ]]; then
    echo "Result: FAIL"
  elif [[ "$UNAVAILABLE_CHECKS" -ne 0 ]]; then
    echo "Result: UNAVAILABLE"
  else
    echo "Result: PASS"
  fi
  echo "---------------------------------------------------------------"
} >> "$SUMMARY"

cat "$SUMMARY"

if [[ "$FAILED_CHECKS" -ne 0 ]]; then
  READINESS_STATUS=FAIL
elif [[ "$UNAVAILABLE_CHECKS" -ne 0 ]]; then
  READINESS_STATUS=UNAVAILABLE
else
  READINESS_STATUS=PASS
fi
qf_json_append_object "$READINESS_JSON" \
  "name=readiness_summary" "status=$READINESS_STATUS" \
  "geiger_policy=$([[ "$STRICT_GEIGER" -eq 1 ]] && echo strict || echo deny-only)" \
  "geiger_dependency_unsafe_count=int:$GEIGER_UNSAFE_DEPS" \
  "geiger_dependency_unsafe_packages=json:$GEIGER_UNSAFE_PACKAGES_JSON" \
  "total_checks=int:$TOTAL_CHECKS" "failed_checks=int:$FAILED_CHECKS" \
  "unavailable_checks=int:$UNAVAILABLE_CHECKS"
json_end "$READINESS_JSON"

if [[ "$READINESS_STATUS" != "PASS" ]]; then
  exit 1
fi

exit 0
