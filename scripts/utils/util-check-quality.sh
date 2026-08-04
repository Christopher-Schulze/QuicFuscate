#!/usr/bin/env bash
# Description: General utility: util-check-quality.
set -euo pipefail

# Quality assurance script for QuicFuscate (robust + artifacts).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../tests/lib/lib-common.sh" || { echo "ERROR: lib-common.sh not found at $SCRIPT_DIR/../tests/lib/lib-common.sh" >&2; exit 1; }

OUTPUT_DIR=""
STRICT=1
MODE="strict"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) export JOBS="$2"; shift;;
    --features) export CARGO_FEATURES="$2"; shift;;
    --strict) STRICT=1; MODE="strict";;
    --advisory) STRICT=0; MODE="advisory";;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--strict|--advisory] [options]"; echo "Quality check (strict blocking mode is the default)"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/quality-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_check_quality"
QUALITY_FAILURES=0
QUALITY_UNAVAILABLE=0

run_quality_command() {
  local name="$1"
  shift
  set +e
  run "$@"
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    qf_json_append_object "$JSON" "name=$name" "status=PASS" "command_rc=int:$rc"
  else
    QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
    qf_json_append_object "$JSON" "name=$name" "status=FAIL" "command_rc=int:$rc"
  fi
  return 0
}

echo "[INFO] QuicFuscate Quality Check"
print_system_banner || true

info "[INFO] Building with strict warnings..."
run_quality_command "release_build" run_cargo build --release

info "[INFO] Running unit tests..."
# Release-quality gate: validate the shipping test surface.
run_quality_command "release_unit_tests" run_cargo test --release --quiet

if command -v cargo-clippy &> /dev/null; then
  info "[INFO] Running clippy analysis..."
  set +e
  if [[ "${CLIPPY_ALL_FEATURES:-0}" == "1" ]]; then
    run cargo clippy --workspace --all-targets --all-features -- -D warnings | tee "$OUTPUT_DIR/clippy.txt"
  else
    # Default release hygiene: validate the shipping surface, not experimental optional features.
    run cargo clippy --workspace --all-targets -- -D warnings | tee "$OUTPUT_DIR/clippy.txt"
  fi
  clippy_rc=${PIPESTATUS[0]}
  set -e
  if [[ "$clippy_rc" -eq 0 ]]; then
    qf_json_append_object "$JSON" "name=clippy" "status=PASS" "command_rc=int:$clippy_rc" "evidence=$OUTPUT_DIR/clippy.txt"
  else
    QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
    qf_json_append_object "$JSON" "name=clippy" "status=FAIL" "command_rc=int:$clippy_rc" "evidence=$OUTPUT_DIR/clippy.txt"
  fi
else
  warn "cargo-clippy not available, skipping"
  QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
  qf_json_append_object "$JSON" "name=clippy" "status=UNAVAILABLE" "reason=cargo-clippy-not-installed"
fi

if command -v cargo-fmt &> /dev/null; then
  info "[INFO] Checking code formatting..."
  set +e
  run cargo fmt --check | tee "$OUTPUT_DIR/fmt.txt"
  fmt_rc=${PIPESTATUS[0]}
  set -e
  if [[ "$fmt_rc" -eq 0 ]]; then
    qf_json_append_object "$JSON" "name=cargo_fmt" "status=PASS" "command_rc=int:$fmt_rc" "evidence=$OUTPUT_DIR/fmt.txt"
  else
    QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
    qf_json_append_object "$JSON" "name=cargo_fmt" "status=FAIL" "command_rc=int:$fmt_rc" "evidence=$OUTPUT_DIR/fmt.txt"
  fi
else
  warn "rustfmt not available, skipping"
  QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
  qf_json_append_object "$JSON" "name=cargo_fmt" "status=UNAVAILABLE" "reason=rustfmt-not-installed"
fi

info "[INFO] Performance smoke test..."
run_quality_command "performance_smoke" run_cargo test --release --lib test_product_fec_default_is_auto --quiet

if command -v cargo-audit &> /dev/null; then
  info "[INFO] Security audit..."
  set +e
  run cargo audit | tee "$OUTPUT_DIR/audit.txt"
  audit_rc=${PIPESTATUS[0]}
  set -e
  if [[ "$audit_rc" -eq 0 ]]; then
    qf_json_append_object "$JSON" "name=cargo_audit" "status=PASS" "command_rc=int:$audit_rc" "evidence=$OUTPUT_DIR/audit.txt"
  elif grep -Eqi 'advisory database|failed to prepare fetch|IO error|network|couldn.t fetch' "$OUTPUT_DIR/audit.txt"; then
    QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
    qf_json_append_object "$JSON" "name=cargo_audit" "status=UNAVAILABLE" "command_rc=int:$audit_rc" "evidence=$OUTPUT_DIR/audit.txt"
  else
    QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
    qf_json_append_object "$JSON" "name=cargo_audit" "status=FAIL" "command_rc=int:$audit_rc" "evidence=$OUTPUT_DIR/audit.txt"
  fi
else
  warn "cargo-audit not available, skipping"
  QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
  qf_json_append_object "$JSON" "name=cargo_audit" "status=UNAVAILABLE" "reason=cargo-audit-not-installed"
fi

# ShellCheck across all scripts if available
if command -v shellcheck >/dev/null 2>&1; then
  info "[INFO] ShellCheck analysis across scripts..."
  SC_OUT="$OUTPUT_DIR/shellcheck.txt"
  mapfile -t SHS < <(find "$SCRIPT_DIR/../.." -type f -name '*.sh' -not -path '*/out/*' | sort)
  : > "$SC_OUT"
  SC_ISSUES=0
  SC_TOOL_FAILURES=0
  SC_FILES=0
  for shf in "${SHS[@]}"; do
    SC_FILES=$((SC_FILES + 1))
    set +e
    shellcheck -S warning -x "$shf" >> "$SC_OUT" 2>&1
    shellcheck_rc=$?
    set -e
    if [[ "$shellcheck_rc" -gt 1 ]]; then
      SC_TOOL_FAILURES=$((SC_TOOL_FAILURES + 1))
    fi
  done
  SC_ISSUES=$(grep -Ec "SC[0-9]+:" "$SC_OUT" || true)
  shellcheck_status="PASS"
  if [[ "$SC_TOOL_FAILURES" -gt 0 ]]; then
    shellcheck_status="UNAVAILABLE"
  elif [[ "$SC_ISSUES" -gt 0 ]]; then
    shellcheck_status="FAIL"
  fi
  info "ShellCheck issues: $SC_ISSUES across $SC_FILES files (see $SC_OUT)"
  qf_json_append_object "$JSON" "name=shellcheck" "status=$shellcheck_status" \
    "mode=$MODE" "files=int:$SC_FILES" "issues=int:$SC_ISSUES" \
    "tool_failures=int:$SC_TOOL_FAILURES" "evidence=$SC_OUT"
  if [[ "$shellcheck_status" == "FAIL" ]]; then
    QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
  elif [[ "$shellcheck_status" == "UNAVAILABLE" ]]; then
    QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
  fi
else
  warn "shellcheck not installed; skipping"
  QUALITY_UNAVAILABLE=$((QUALITY_UNAVAILABLE + 1))
  qf_json_append_object "$JSON" "name=shellcheck" "status=UNAVAILABLE" \
    "mode=$MODE" "reason=shellcheck-not-installed"
fi

info "[INFO] Script consistency analysis..."
set +e
bash scripts/tests/analysis/analysis-scripts-quality.sh --strict --output-dir "$OUTPUT_DIR/scripts-quality" | tee "$OUTPUT_DIR/scripts-quality.txt"
scripts_quality_rc=${PIPESTATUS[0]}
bash scripts/tests/analysis/analysis-suite-matrix.sh --output-dir "$OUTPUT_DIR/suite-matrix" | tee "$OUTPUT_DIR/suite-matrix.txt"
suite_matrix_rc=${PIPESTATUS[0]}
set -e
if [[ "$scripts_quality_rc" -eq 0 ]]; then
  qf_json_append_object "$JSON" "name=analysis_scripts_quality" "status=PASS" "command_rc=int:$scripts_quality_rc" "evidence=$OUTPUT_DIR/scripts-quality/results.json"
else
  QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
  qf_json_append_object "$JSON" "name=analysis_scripts_quality" "status=FAIL" "command_rc=int:$scripts_quality_rc" "evidence=$OUTPUT_DIR/scripts-quality/results.json"
fi
if [[ "$suite_matrix_rc" -eq 0 ]]; then
  qf_json_append_object "$JSON" "name=analysis_suite_matrix" "status=PASS" "command_rc=int:$suite_matrix_rc" "evidence=$OUTPUT_DIR/suite-matrix/results.json"
else
  QUALITY_FAILURES=$((QUALITY_FAILURES + 1))
  qf_json_append_object "$JSON" "name=analysis_suite_matrix" "status=FAIL" "command_rc=int:$suite_matrix_rc" "evidence=$OUTPUT_DIR/suite-matrix/results.json"
fi

echo ""; echo "[OK] Quality check completed. Artifacts: $OUTPUT_DIR"
if [[ "$QUALITY_FAILURES" -gt 0 ]]; then
  QUALITY_STATUS=FAIL
elif [[ "$QUALITY_UNAVAILABLE" -gt 0 ]]; then
  QUALITY_STATUS=UNAVAILABLE
else
  QUALITY_STATUS=PASS
fi
qf_json_append_object "$JSON" "name=quality_summary" "status=$QUALITY_STATUS" \
  "mode=$MODE" "failures=int:$QUALITY_FAILURES" "unavailable=int:$QUALITY_UNAVAILABLE"
json_end "$JSON"

if [[ "$STRICT" -eq 1 && "$QUALITY_STATUS" != "PASS" ]]; then
  exit 1
fi
