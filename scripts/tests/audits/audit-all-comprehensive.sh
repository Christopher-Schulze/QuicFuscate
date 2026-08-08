#!/usr/bin/env bash
# Description: Audit runner: audit-all-comprehensive.
# shellcheck source=scripts/tests/lib/lib-common.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
# Every expected nonzero probe below is captured and classified explicitly;
# suppress the shared ERR trap so expected findings do not masquerade as shell failures.
trap - ERR
ALLOWLIST_FILE="$SCRIPT_DIR/allowlists/critical-allowlist.txt"

OUTPUT_DIR=""
STRICT=1
MODE="strict"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --strict) STRICT=1; MODE="strict";;
    --advisory) STRICT=0; MODE="advisory";;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--strict|--advisory] [--output-dir DIR] [--verbose]"; echo "Comprehensive Security & Quality Audit (strict blocking mode is the default)"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

echo "==============================================================="
echo "  QuicFuscate Comprehensive Security & Quality Audit"
echo "==============================================================="
echo "  Starting at: $(date)"
echo "==============================================================="

# Audit results tracking
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/audit-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
AUDIT_LOG="$OUTPUT_DIR/audit.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "audit_all"

WARNINGS_FOUND=0
CRITICAL_ISSUES=0
CHECK_FAILURES=0
CHECK_UNAVAILABLE=0

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log_critical() {
    echo -e "${RED}[FAIL] CRITICAL: $1${NC}" | tee -a "$AUDIT_LOG"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARN]  WARNING: $1${NC}" | tee -a "$AUDIT_LOG"
    WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
}

log_info() {
    echo -e "${GREEN}[OK] $1${NC}" | tee -a "$AUDIT_LOG"
}

record_check() {
    local name="$1"
    local status="$2"
    local command_rc="${3:-}"
    local evidence="${4:-}"
    case "$status" in
        PASS|FAIL|UNAVAILABLE) ;;
        *)
            echo "Invalid audit check status: $status" >&2
            return 2
            ;;
    esac
    if [[ -n "$command_rc" ]]; then
        qf_json_append_object "$JSON" \
          "name=$name" "status=$status" "command_rc=int:$command_rc" "evidence=$evidence"
    else
        qf_json_append_object "$JSON" \
          "name=$name" "status=$status" "command_rc=null" "evidence=$evidence"
    fi
    case "$status" in
        FAIL) CHECK_FAILURES=$((CHECK_FAILURES + 1));;
        UNAVAILABLE) CHECK_UNAVAILABLE=$((CHECK_UNAVAILABLE + 1));;
    esac
}

record_command_check() {
    local name="$1"
    local command_rc="$2"
    local evidence="$3"
    if [[ "$command_rc" -eq 0 ]]; then
        record_check "$name" PASS "$command_rc" "$evidence"
    else
        record_check "$name" FAIL "$command_rc" "$evidence"
    fi
}

record_search_check() {
    local name="$1"
    local command_rc="$2"
    local evidence="$3"
    if [[ "$command_rc" -eq 0 || "$command_rc" -eq 1 ]]; then
        record_check "$name" PASS "$command_rc" "$evidence"
    else
        record_check "$name" FAIL "$command_rc" "$evidence"
    fi
}

for required_command in cargo find grep python3 rg sed; do
    if command -v "$required_command" >/dev/null 2>&1; then
        record_check "preflight_$required_command" PASS "" "tool=$required_command"
    else
        log_critical "Required audit command is unavailable: $required_command"
        record_check "preflight_$required_command" UNAVAILABLE "" "tool=$required_command"
    fi
done

count_lines() {
    wc -l | tr -d '[:space:]'
}

allowlist_regex() {
    local kind="$1"
    [[ -f "$ALLOWLIST_FILE" ]] || return 0
    awk -v kind="$kind" '
        {
            sep = index($0, "|")
            if (sep <= 0) next
            k = substr($0, 1, sep - 1)
            p = substr($0, sep + 1)
        }
        k == kind && p != "" {
            if (out != "") out = out "|" p; else out = p
        }
        END { print out }
    ' "$ALLOWLIST_FILE"
}

split_locations_with_allowlist() {
    local kind="$1"
    local locations="$2"
    local rx
    rx="$(allowlist_regex "$kind")"
    if [[ -n "$rx" ]]; then
        TOLERATED_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d' | grep -E "$rx" || true)"
        BLOCKER_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d' | grep -Ev "$rx" || true)"
    else
        TOLERATED_LOCATIONS=""
        BLOCKER_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d')"
    fi
}

# Security Audit
echo -e "\n+===============================================================+"
echo "|                    SECURITY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing unsafe code usage..."
RUST_SCOPE_LOG="$OUTPUT_DIR/rust-scope.json"
set +e
python3 "$SCRIPT_DIR/audit-rust-scope.py" --root "$PROJECT_ROOT" >"$RUST_SCOPE_LOG" 2>&1
RUST_SCOPE_RC=$?
set -e
record_command_check "rust_production_scope" "$RUST_SCOPE_RC" "artifact=$RUST_SCOPE_LOG"
UNSAFE_IN_PROD=0
LEAK_COUNT=0
if [ "$RUST_SCOPE_RC" -eq 0 ]; then
    set +e
    RUST_SCOPE_COUNTS=$(python3 - "$RUST_SCOPE_LOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
print(report["unsafe_count"], report["leak_pattern_count"])
PY
    )
    RUST_SCOPE_PARSE_RC=$?
    set -e
    record_command_check "rust_production_scope_parse" "$RUST_SCOPE_PARSE_RC" "artifact=$RUST_SCOPE_LOG"
    if [ "$RUST_SCOPE_PARSE_RC" -eq 0 ]; then
        read -r UNSAFE_IN_PROD LEAK_COUNT <<<"$RUST_SCOPE_COUNTS"
    else
        log_critical "Rust production-scope report could not be parsed"
    fi
else
    log_critical "Rust production-scope scan failed with rc=$RUST_SCOPE_RC"
fi
if [ "$UNSAFE_IN_PROD" -gt 50 ]; then
    log_warning "High unsafe usage in production scope: $UNSAFE_IN_PROD occurrences"
else
    log_info "Unsafe usage in production scope: $UNSAFE_IN_PROD occurrences"
fi

echo -e "\n> Checking for panic-inducing code..."
STRICT_RUNTIME_CLIPPY="$OUTPUT_DIR/strict-runtime-clippy.log"
set +e
RUNTIME_CLIPPY_OUTPUT=$(cargo clippy --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic 2>&1)
RUNTIME_CLIPPY_RC=$?
set -e
printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" > "$STRICT_RUNTIME_CLIPPY"
record_command_check "strict_runtime_clippy" "$RUNTIME_CLIPPY_RC" "artifact=$STRICT_RUNTIME_CLIPPY"

UNWRAP_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'used `unwrap()' || true)
EXPECT_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'used `expect(' || true)
PANIC_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'should not be present in production code' || true)

if [ "$UNWRAP_COUNT" -gt 0 ]; then
    log_warning "Found $UNWRAP_COUNT unwrap() usages in runtime code (clippy strict)"
    echo "  Locations:" | tee -a "$AUDIT_LOG"
    printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | rg -n -- '--> src/' | head -5 | tee -a "$AUDIT_LOG" || true
fi

if [ "$EXPECT_COUNT" -gt 0 ]; then
    log_warning "Found $EXPECT_COUNT expect() usages in runtime code (clippy strict)"
fi

if [ "$PANIC_COUNT" -gt 0 ]; then
    log_critical "Found $PANIC_COUNT panic! usages in runtime code (clippy strict)"
fi
if [ "$RUNTIME_CLIPPY_RC" -ne 0 ]; then
    log_critical "Strict runtime Clippy command failed with rc=$RUNTIME_CLIPPY_RC"
fi

echo -e "\n> Checking for hardcoded secrets..."
SECRET_SCOPE_LOG="$OUTPUT_DIR/secret-scope.json"
set +e
python3 "$SCRIPT_DIR/audit-secret-scope.py" --root "$PROJECT_ROOT" >"$SECRET_SCOPE_LOG" 2>&1
SECRET_SCOPE_RC=$?
set -e
record_command_check "secret_scope_scan" "$SECRET_SCOPE_RC" "artifact=$SECRET_SCOPE_LOG"
SECRET_COUNT=0
SECRET_MATCHES=""
if [ "$SECRET_SCOPE_RC" -eq 0 ]; then
    set +e
    SECRET_SCOPE_COUNTS=$(python3 - "$SECRET_SCOPE_LOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
print(report.get("status", "UNAVAILABLE"), report.get("secret_count", 0))
for location in report["locations"][:3]:
    print(f'{location["path"]}:{location["line"]}:{location["kind"]}')
PY
    )
    SECRET_SCOPE_PARSE_RC=$?
    set -e
    record_command_check "secret_scope_parse" "$SECRET_SCOPE_PARSE_RC" "artifact=$SECRET_SCOPE_LOG"
    if [ "$SECRET_SCOPE_PARSE_RC" -eq 0 ]; then
        SECRET_SCOPE_STATUS="${SECRET_SCOPE_COUNTS%%$'\n'*}"
        read -r SECRET_SCOPE_STATUS SECRET_COUNT <<<"$SECRET_SCOPE_STATUS"
        SECRET_MATCHES="${SECRET_SCOPE_COUNTS#*$'\n'}"
        if [ "$SECRET_MATCHES" = "$SECRET_SCOPE_COUNTS" ]; then
            SECRET_MATCHES=""
        fi
        record_check "secret_scope_result" "$SECRET_SCOPE_STATUS" "" "artifact=$SECRET_SCOPE_LOG"
    else
        log_critical "Secret-scope report could not be parsed"
    fi
else
    log_critical "Secret-scope scan failed with rc=$SECRET_SCOPE_RC"
fi
if [ "$SECRET_COUNT" -gt 0 ]; then
    log_critical "Hardcoded secret literals detected: $SECRET_COUNT occurrences"
    printf "%s\n" "$SECRET_MATCHES" | tee -a "$AUDIT_LOG"
else
    log_info "No hardcoded secrets detected"
fi

echo -e "\n> Validating syntax by consumer dialect..."
DIALECT_LOG="$OUTPUT_DIR/dialect-validation.json"
set +e
python3 "$SCRIPT_DIR/../analysis/analysis-dialect-validation.py" --root "$PROJECT_ROOT" >"$DIALECT_LOG" 2>&1
DIALECT_RC=$?
set -e
record_command_check "dialect_validation_scan" "$DIALECT_RC" "artifact=$DIALECT_LOG"
if [ "$DIALECT_RC" -eq 0 ]; then
    set +e
    DIALECT_SUMMARY=$(python3 - "$DIALECT_LOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
print(report.get("status", "UNAVAILABLE"), report.get("failures", 0), report.get("unavailable", 0))
PY
    )
    DIALECT_PARSE_RC=$?
    set -e
    record_command_check "dialect_validation_parse" "$DIALECT_PARSE_RC" "artifact=$DIALECT_LOG"
    if [ "$DIALECT_PARSE_RC" -eq 0 ]; then
        read -r DIALECT_STATUS DIALECT_FAILURES DIALECT_UNAVAILABLE <<<"$DIALECT_SUMMARY"
        record_check "dialect_validation_result" "$DIALECT_STATUS" "" "artifact=$DIALECT_LOG"
        if [ "$DIALECT_STATUS" = "FAIL" ]; then
            log_critical "Dialect validation reported $DIALECT_FAILURES syntax failures"
        elif [ "$DIALECT_STATUS" = "UNAVAILABLE" ]; then
            log_warning "Dialect validation has $DIALECT_UNAVAILABLE unavailable native parser results"
        else
            log_info "Dialect validation passed"
        fi
    else
        log_critical "Dialect validation report could not be parsed"
    fi
else
    log_critical "Dialect validation command failed with rc=$DIALECT_RC"
fi

echo -e "\n> Checking memory safety..."
if [ "$LEAK_COUNT" -gt 0 ]; then
    log_warning "Potential memory-management patterns in production scope: $LEAK_COUNT found"
fi

# Dependency Audit
echo -e "\n+===============================================================+"
echo "|                  DEPENDENCY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Checking for vulnerable dependencies..."
DEPENDENCY_AUDIT_LOG="$OUTPUT_DIR/cargo-audit.log"
if command -v cargo-audit &> /dev/null; then
    set +e
    AUDIT_OUTPUT=$(cargo audit 2>&1)
    AUDIT_RC=$?
    set -e
    printf "%s\n" "$AUDIT_OUTPUT" > "$DEPENDENCY_AUDIT_LOG"
    if [ "$AUDIT_RC" -ne 0 ]; then
        if printf "%s\n" "$AUDIT_OUTPUT" | grep -Eqi "couldn't fetch advisory database|advisory database|IO error|failed to prepare fetch|network"; then
            log_warning "cargo audit is unavailable with rc=$AUDIT_RC because its advisory database could not be fetched"
            record_check "cargo_audit" UNAVAILABLE "$AUDIT_RC" "artifact=$DEPENDENCY_AUDIT_LOG"
        else
            log_critical "cargo audit command failed with rc=$AUDIT_RC"
            record_check "cargo_audit" FAIL "$AUDIT_RC" "artifact=$DEPENDENCY_AUDIT_LOG"
        fi
    else
        record_check "cargo_audit" PASS "$AUDIT_RC" "artifact=$DEPENDENCY_AUDIT_LOG"
    fi
    VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Vulnerability" || true)
    if [ "$VULN_COUNT" -gt 0 ]; then
        log_critical "Found $VULN_COUNT vulnerable dependencies"
        echo "$AUDIT_OUTPUT" | grep "Vulnerability" | head -5 | tee -a "$AUDIT_LOG" || true
    elif [ "$AUDIT_RC" -eq 0 ]; then
        log_info "No known vulnerabilities in dependencies"
    else
        log_warning "Dependency vulnerability result is unavailable because cargo audit failed"
    fi
else
    log_warning "cargo-audit not installed, skipping vulnerability check"
    record_check "cargo_audit" UNAVAILABLE "" "reason=cargo-audit-not-installed"
fi

echo -e "\n> Checking dependency licenses..."
DEPENDENCY_TREE_LOG="$OUTPUT_DIR/cargo-tree.log"
set +e
cargo tree --no-dedupe >"$DEPENDENCY_TREE_LOG" 2>&1
DEPENDENCY_TREE_RC=$?
set -e
record_command_check "cargo_tree" "$DEPENDENCY_TREE_RC" "artifact=$DEPENDENCY_TREE_LOG"
TOTAL_DEPS=$(wc -l < "$DEPENDENCY_TREE_LOG" | tr -d '[:space:]')
if [ "$DEPENDENCY_TREE_RC" -ne 0 ]; then
    log_critical "cargo tree command failed with rc=$DEPENDENCY_TREE_RC"
else
    log_info "Total dependencies: $TOTAL_DEPS"
fi

echo -e "\n> Checking cargo-deny policy and warning state..."
CARGO_DENY_LOG="$OUTPUT_DIR/cargo-deny.log"
if command -v cargo-deny >/dev/null 2>&1; then
    set +e
    cargo deny --locked check >"$CARGO_DENY_LOG" 2>&1
    CARGO_DENY_RC=$?
    set -e
    CARGO_DENY_WARNINGS=$(grep -Ec '(^|[[:space:]])warning([:!]|[[:space:]])' "$CARGO_DENY_LOG" || true)
    if [ "$CARGO_DENY_RC" -ne 0 ]; then
        if grep -Eqi 'advisory database|failed to prepare fetch|IO error|network|couldn.t fetch' "$CARGO_DENY_LOG"; then
            record_check "cargo_deny" UNAVAILABLE "$CARGO_DENY_RC" "artifact=$CARGO_DENY_LOG"
            log_warning "cargo deny is unavailable with rc=$CARGO_DENY_RC because its advisory database could not be fetched"
        else
            record_check "cargo_deny" FAIL "$CARGO_DENY_RC" "artifact=$CARGO_DENY_LOG"
            log_critical "cargo deny command failed with rc=$CARGO_DENY_RC"
        fi
    elif [ "$CARGO_DENY_WARNINGS" -gt 0 ]; then
        record_check "cargo_deny" FAIL "$CARGO_DENY_RC" "artifact=$CARGO_DENY_LOG"
        log_warning "cargo deny passed with $CARGO_DENY_WARNINGS warning lines; policy result is not clean"
    else
        record_check "cargo_deny" PASS "$CARGO_DENY_RC" "artifact=$CARGO_DENY_LOG"
        log_info "cargo deny policy passed without warnings"
    fi
else
    record_check "cargo_deny" UNAVAILABLE "" "reason=cargo-deny-not-installed"
    log_warning "cargo-deny not installed, dependency-policy result is unavailable"
fi

# Performance Audit
echo -e "\n+===============================================================+"
echo "|                 PERFORMANCE AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing hot path optimizations..."
INLINE_ALWAYS=$(grep -r "#\[inline(always)\]" src/ --include="*.rs" | wc -l)
INLINE_REGULAR=$(grep -r "#\[inline\]" src/ --include="*.rs" | grep -vc "inline(always)" || true)
log_info "Inline annotations: $INLINE_ALWAYS always, $INLINE_REGULAR regular"

echo -e "\n> Checking for performance anti-patterns..."
CLONE_LINT_LOG="$OUTPUT_DIR/clone-lints.log"
set +e
CLONE_LINT_OUTPUT=$(cargo clippy --lib --bins --all-features -- -W clippy::redundant_clone -W clippy::clone_on_copy -W clippy::iter_cloned_collect 2>&1)
CLONE_LINT_RC=$?
set -e
printf "%s\n" "$CLONE_LINT_OUTPUT" > "$CLONE_LINT_LOG"
record_command_check "clone_lints" "$CLONE_LINT_RC" "artifact=$CLONE_LINT_LOG"
if [ "$CLONE_LINT_RC" -ne 0 ]; then
    log_critical "Clone lint command failed with rc=$CLONE_LINT_RC"
fi
AVOIDABLE_CLONE_COUNT=$(printf "%s\n" "$CLONE_LINT_OUTPUT" | grep -Ec "clippy::(redundant_clone|clone_on_copy|iter_cloned_collect)" || true)
if [ "$AVOIDABLE_CLONE_COUNT" -gt 0 ]; then
    log_warning "Avoidable clone patterns found: $AVOIDABLE_CLONE_COUNT (see clone-lints.log)"
else
    log_info "No avoidable clone patterns detected by strict clone lints"
fi

COLLECT_COUNT=$(grep -r "\.collect::<Vec" src/ --include="*.rs" | wc -l)
if [ "$COLLECT_COUNT" -gt 50 ]; then
    log_warning "High collect usage: $COLLECT_COUNT calls (consider iterators)"
fi

echo -e "\n> Analyzing SIMD usage..."
SIMD_FEATURES=$(grep -r "target_arch\|target_feature" src/ --include="*.rs" | wc -l)
if [ "$SIMD_FEATURES" -lt 10 ]; then
    log_warning "Low SIMD usage: only $SIMD_FEATURES conditionals found"
else
    log_info "Good SIMD coverage: $SIMD_FEATURES feature conditionals"
fi

SIMD_FEATURE_CONTRACT_LOG="$OUTPUT_DIR/simd-feature-contract.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-simd-feature-contract.sh" >"$SIMD_FEATURE_CONTRACT_LOG" 2>&1
SIMD_FEATURE_CONTRACT_RC=$?
set -e
record_command_check "simd_feature_contract" "$SIMD_FEATURE_CONTRACT_RC" "artifact=$SIMD_FEATURE_CONTRACT_LOG"
if [ "$SIMD_FEATURE_CONTRACT_RC" -eq 0 ]; then
    log_info "Cargo SIMD feature contract passed"
else
    log_critical "Cargo SIMD feature contract failed with rc=$SIMD_FEATURE_CONTRACT_RC (see $SIMD_FEATURE_CONTRACT_LOG)"
fi

AMX_PROOF_CONTRACT_LOG="$OUTPUT_DIR/amx-proof-contract.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-amx-proof-contract.sh" >"$AMX_PROOF_CONTRACT_LOG" 2>&1
AMX_PROOF_CONTRACT_RC=$?
set -e
record_command_check "amx_proof_contract" "$AMX_PROOF_CONTRACT_RC" "artifact=$AMX_PROOF_CONTRACT_LOG"
if [ "$AMX_PROOF_CONTRACT_RC" -eq 0 ]; then
    log_info "AMX build/runtime proof contract passed"
else
    log_critical "AMX build/runtime proof contract failed with rc=$AMX_PROOF_CONTRACT_RC (see $AMX_PROOF_CONTRACT_LOG)"
fi

AMX_PROOF_OUTPUT_DIR="$OUTPUT_DIR/amx-proof"
set +e
"$PROJECT_ROOT/scripts/tests/suites/test-amx-proof.sh" --output-dir "$AMX_PROOF_OUTPUT_DIR"
AMX_PROOF_RC=$?
set -e
case "$AMX_PROOF_RC" in
    0)
        record_check "amx_proof_lane" PASS "$AMX_PROOF_RC" "artifact=$AMX_PROOF_OUTPUT_DIR/results.json"
        log_info "AMX build/runtime proof lane passed"
        ;;
    2)
        record_check "amx_proof_lane" UNAVAILABLE "$AMX_PROOF_RC" "artifact=$AMX_PROOF_OUTPUT_DIR/results.json"
        log_warning "AMX build/runtime proof lane is explicitly unavailable on this host"
        ;;
    *)
        record_check "amx_proof_lane" FAIL "$AMX_PROOF_RC" "artifact=$AMX_PROOF_OUTPUT_DIR/results.json"
        log_critical "AMX build/runtime proof lane failed with rc=$AMX_PROOF_RC"
        ;;
esac

CARGO_FEATURE_TAXONOMY_LOG="$OUTPUT_DIR/cargo-feature-taxonomy.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-cargo-feature-taxonomy.sh" >"$CARGO_FEATURE_TAXONOMY_LOG" 2>&1
CARGO_FEATURE_TAXONOMY_RC=$?
set -e
record_command_check "cargo_feature_taxonomy" "$CARGO_FEATURE_TAXONOMY_RC" "artifact=$CARGO_FEATURE_TAXONOMY_LOG"
if [ "$CARGO_FEATURE_TAXONOMY_RC" -eq 0 ]; then
    log_info "Cargo feature taxonomy contract passed"
else
    log_critical "Cargo feature taxonomy contract failed with rc=$CARGO_FEATURE_TAXONOMY_RC (see $CARGO_FEATURE_TAXONOMY_LOG)"
fi

WEB_ADMIN_PUBLISH_CONTRACT_LOG="$OUTPUT_DIR/web-admin-publish-contract.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-web-admin-publish-contract.sh" >"$WEB_ADMIN_PUBLISH_CONTRACT_LOG" 2>&1
WEB_ADMIN_PUBLISH_CONTRACT_RC=$?
set -e
record_command_check "web_admin_publish_contract" "$WEB_ADMIN_PUBLISH_CONTRACT_RC" "artifact=$WEB_ADMIN_PUBLISH_CONTRACT_LOG"
if [ "$WEB_ADMIN_PUBLISH_CONTRACT_RC" -eq 0 ]; then
    log_info "Generated web-admin publish contract passed"
else
    log_critical "Generated web-admin publish contract failed with rc=$WEB_ADMIN_PUBLISH_CONTRACT_RC (see $WEB_ADMIN_PUBLISH_CONTRACT_LOG)"
fi

TLS_CLIENTHELLO_CONTRACT_LOG="$OUTPUT_DIR/tls-clienthello-contract.log"
set +e
"$PROJECT_ROOT/scripts/audits/verify-tls-clienthello-contract.sh" >"$TLS_CLIENTHELLO_CONTRACT_LOG" 2>&1
TLS_CLIENTHELLO_CONTRACT_RC=$?
set -e
record_command_check "tls_clienthello_contract" "$TLS_CLIENTHELLO_CONTRACT_RC" "artifact=$TLS_CLIENTHELLO_CONTRACT_LOG"
if [ "$TLS_CLIENTHELLO_CONTRACT_RC" -eq 0 ]; then
    log_info "TLS ClientHello ownership contract passed"
else
    log_critical "TLS ClientHello ownership contract failed with rc=$TLS_CLIENTHELLO_CONTRACT_RC (see $TLS_CLIENTHELLO_CONTRACT_LOG)"
fi

echo -e "\n> Checking allocations in hot paths..."
HOT_PATH_ALLOC_LOG="$OUTPUT_DIR/hot-path-allocation.log"
set +e
HOT_PATH_ALLOCS=$(
python3 - 2>"$HOT_PATH_ALLOC_LOG" <<'PY'
import pathlib, re
files = ["src/transport/connection/mod.rs", "src/transport/packet.rs", "src/crypto/mod.rs"]
alloc = re.compile(r"\b(Vec::new|String::new|Box::new|to_vec\()")
loop = re.compile(r"\b(for|while|loop)\b")
comment = re.compile(r"^\s*//")
count = 0
for f in files:
    lines = pathlib.Path(f).read_text().splitlines()
    for i, line in enumerate(lines):
        if comment.match(line):
            continue
        if loop.search(line):
            window = "\n".join(x for x in lines[i:i + 10] if not comment.match(x))
            if alloc.search(window):
                count += 1
print(count)
PY
)
HOT_PATH_ALLOC_RC=$?
set -e
record_command_check "hot_path_allocation_probe" "$HOT_PATH_ALLOC_RC" "artifact=$HOT_PATH_ALLOC_LOG"
if ! [[ "$HOT_PATH_ALLOCS" =~ ^[0-9]+$ ]]; then
    HOT_PATH_ALLOCS=0
fi
if [ "$HOT_PATH_ALLOC_RC" -ne 0 ]; then
    log_critical "Hot-path allocation probe failed with rc=$HOT_PATH_ALLOC_RC"
fi
if [ "$HOT_PATH_ALLOCS" -gt 8 ]; then
    log_warning "High loop-adjacent allocations in hot paths: $HOT_PATH_ALLOCS found"
else
    log_info "Loop-adjacent allocations in hot paths acceptable: $HOT_PATH_ALLOCS"
fi

# Code Quality Audit
echo -e "\n+===============================================================+"
echo "|                  CODE QUALITY AUDIT                            |"
echo "+===============================================================+"

echo -e "\n> Running Clippy analysis..."
set +e
CLIPPY_OUTPUT=$(cargo clippy --all-targets --all-features -- -W clippy::all 2>&1)
CLIPPY_RC=$?
set -e
CLIPPY_LOG="$OUTPUT_DIR/clippy.log"
printf "%s\n" "$CLIPPY_OUTPUT" > "$CLIPPY_LOG"
record_command_check "clippy_all_targets" "$CLIPPY_RC" "artifact=$CLIPPY_LOG"
CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "warning:" || true)
CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "error:" || true)

if [ "$CLIPPY_ERRORS" -gt 0 ]; then
    log_critical "Clippy found $CLIPPY_ERRORS errors"
elif [ "$CLIPPY_WARNINGS" -gt 50 ]; then
    log_warning "Clippy found $CLIPPY_WARNINGS warnings"
else
    log_info "Clippy warnings acceptable: $CLIPPY_WARNINGS"
fi
if [ "$CLIPPY_RC" -ne 0 ]; then
    log_critical "Code quality Clippy command failed with rc=$CLIPPY_RC"
fi

echo -e "\n> Checking for commented-out code blocks..."
COMMENTED_CODE_RE='^\s*//\s*(pub\s+(struct|enum|trait|mod|fn|const|type)\b|fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|impl\b|let\s+[A-Za-z_][A-Za-z0-9_]*\s*=|if\s*\(|for\s+[A-Za-z_][A-Za-z0-9_]*\s+in\b|while\s+|match\s+[A-Za-z_0-9_:]+\s*\{|use\s+[A-Za-z_][A-Za-z0-9_:]*(\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;|mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;)'
COMMENTED_CODE_LOG="$OUTPUT_DIR/commented-code-scan.log"
set +e
COMMENTED_CODE_LOCATIONS="$(rg -n --no-heading -e "$COMMENTED_CODE_RE" src -g '*.rs' -g '!**/tests/**' 2>"$COMMENTED_CODE_LOG")"
COMMENTED_CODE_RC=$?
set -e
record_search_check "commented_code_scan" "$COMMENTED_CODE_RC" "artifact=$COMMENTED_CODE_LOG"
if [ "$COMMENTED_CODE_RC" -gt 1 ]; then
    log_critical "Commented-code scan failed with rc=$COMMENTED_CODE_RC"
fi
COMMENTED_CODE_COUNT=$(printf "%s\n" "$COMMENTED_CODE_LOCATIONS" | sed '/^$/d' | count_lines)
if [ "$COMMENTED_CODE_COUNT" -gt 0 ]; then
    log_warning "Commented-out code detected: $COMMENTED_CODE_COUNT locations"
    printf "%s\n" "$COMMENTED_CODE_LOCATIONS" | head -5 | tee -a "$AUDIT_LOG" || true
else
    log_info "No commented-out code patterns detected in src/"
fi

echo -e "\n> Checking documentation coverage..."
set +e
DOC_OUTPUT=$(cargo doc --no-deps 2>&1)
DOC_RC=$?
set -e
DOC_LOG="$OUTPUT_DIR/cargo-doc.log"
printf "%s\n" "$DOC_OUTPUT" > "$DOC_LOG"
record_command_check "cargo_doc" "$DOC_RC" "artifact=$DOC_LOG"
MISSING_DOCS=$(echo "$DOC_OUTPUT" | grep -c "missing documentation" || true)
if [ "$DOC_RC" -ne 0 ]; then
    log_critical "cargo doc command failed with rc=$DOC_RC"
elif [ "$MISSING_DOCS" -gt 20 ]; then
    log_warning "Poor documentation: $MISSING_DOCS items missing docs"
else
    log_info "Documentation coverage good: $MISSING_DOCS items missing"
fi

echo -e "\n> Checking test-file presence (not executed coverage)..."
TEST_FILES=$(find src -name "*.rs" -exec grep -l "#\[test\]" {} \; | wc -l)
TOTAL_FILES=$(find src -name "*.rs" | wc -l)
TEST_FILE_PRESENCE=$((TEST_FILES * 100 / TOTAL_FILES))
if [ "$TEST_FILE_PRESENCE" -lt 30 ]; then
    log_warning "Low test-file presence: only $TEST_FILE_PRESENCE% of Rust files contain a test marker"
else
    log_info "Test-file presence: $TEST_FILE_PRESENCE% of Rust files contain a test marker"
fi
qf_json_append_object "$JSON" \
  "unsafe_in_prod=int:$UNSAFE_IN_PROD" "unwrap_calls=int:$UNWRAP_COUNT" \
  "panic_macros=int:$PANIC_COUNT" "secrets=int:$SECRET_COUNT" \
  "leak_patterns=int:$LEAK_COUNT" "simd_features=int:$SIMD_FEATURES" \
  "test_file_presence_percent=int:$TEST_FILE_PRESENCE" \
  "test_files=int:$TEST_FILES" "rust_source_files=int:$TOTAL_FILES" \
  "metric_scope=source-marker-presence-not-executed-coverage"

echo -e "\n> Running runtime guardrails..."
set +e
"$SCRIPT_DIR/audit-runtime-guardrails.sh" --output-dir "$OUTPUT_DIR/runtime-guardrails"
RUNTIME_GUARDRAILS_RC=$?
set -e
record_command_check "runtime_guardrails" "$RUNTIME_GUARDRAILS_RC" "artifact=$OUTPUT_DIR/runtime-guardrails/results.json"
if [ "$RUNTIME_GUARDRAILS_RC" -eq 0 ]; then
    log_info "Runtime guardrails passed"
else
    log_critical "Runtime guardrails failed with rc=$RUNTIME_GUARDRAILS_RC (see $OUTPUT_DIR/runtime-guardrails)"
fi

# Complexity Audit
echo -e "\n+===============================================================+"
echo "|                  COMPLEXITY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing function complexity..."
LONG_FUNCTION_LOG="$OUTPUT_DIR/long-function-probe.log"
set +e
LONG_FUNCTIONS=$(
python3 - 2>"$LONG_FUNCTION_LOG" <<'PY'
import glob, pathlib, re
fn_re = re.compile(r'^\s*(pub\s+)?(async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(')
threshold = 300
count = 0

def strip_comments(line: str) -> str:
    return line.split("//", 1)[0]

def function_ranges(lines):
    i = 0
    n = len(lines)
    while i < n:
        if not fn_re.match(lines[i]):
            i += 1
            continue
        start = i
        j = i
        depth = 0
        opened = False
        while j < n:
            text = strip_comments(lines[j])
            if not opened:
                if "{" in text:
                    opened = True
                else:
                    j += 1
                    continue
            depth += text.count("{")
            depth -= text.count("}")
            if opened and depth <= 0:
                break
            j += 1
        end = j if j < n else (n - 1)
        yield start, end
        i = max(i + 1, end + 1)

for path in glob.glob("src/**/*.rs", recursive=True):
    lines = pathlib.Path(path).read_text().splitlines()
    for start, end in function_ranges(lines):
        if (end - start + 1) >= threshold:
            count += 1
print(count)
PY
)
LONG_FUNCTION_RC=$?
set -e
record_command_check "long_function_probe" "$LONG_FUNCTION_RC" "artifact=$LONG_FUNCTION_LOG"
if ! [[ "$LONG_FUNCTIONS" =~ ^[0-9]+$ ]]; then
    LONG_FUNCTIONS=0
fi
if [ "$LONG_FUNCTION_RC" -ne 0 ]; then
    log_critical "Function-complexity probe failed with rc=$LONG_FUNCTION_RC"
fi
if [ "$LONG_FUNCTIONS" -gt 35 ]; then
    log_warning "Many very long functions (>=300 lines): $LONG_FUNCTIONS"
else
    log_info "Very long function count acceptable: $LONG_FUNCTIONS"
fi

echo -e "\n> Checking cyclomatic complexity..."
BRANCH_HOTSPOT_LOG="$OUTPUT_DIR/branch-hotspot-probe.log"
set +e
BRANCH_HOTSPOTS=$(
python3 - 2>"$BRANCH_HOTSPOT_LOG" <<'PY'
import glob, pathlib, re
fn_re = re.compile(r'^\s*(pub\s+)?(async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(')
branch_re = re.compile(r'\b(if|match)\b')
hotspot_threshold = 80
hotspots = 0

def strip_comments(line: str) -> str:
    return line.split("//", 1)[0]

def function_ranges(lines):
    i = 0
    n = len(lines)
    while i < n:
        if not fn_re.match(lines[i]):
            i += 1
            continue
        start = i
        j = i
        depth = 0
        opened = False
        while j < n:
            text = strip_comments(lines[j])
            if not opened:
                if "{" in text:
                    opened = True
                else:
                    j += 1
                    continue
            depth += text.count("{")
            depth -= text.count("}")
            if opened and depth <= 0:
                break
            j += 1
        end = j if j < n else (n - 1)
        yield start, end
        i = max(i + 1, end + 1)

for path in glob.glob("src/**/*.rs", recursive=True):
    lines = pathlib.Path(path).read_text().splitlines()
    for start, end in function_ranges(lines):
        seg = [strip_comments(ln) for ln in lines[start:end + 1]]
        branches = sum(1 for ln in seg if branch_re.search(ln))
        if branches >= hotspot_threshold:
            hotspots += 1
print(hotspots)
PY
)
BRANCH_HOTSPOT_RC=$?
set -e
record_command_check "branch_hotspot_probe" "$BRANCH_HOTSPOT_RC" "artifact=$BRANCH_HOTSPOT_LOG"
if ! [[ "$BRANCH_HOTSPOTS" =~ ^[0-9]+$ ]]; then
    BRANCH_HOTSPOTS=0
fi
if [ "$BRANCH_HOTSPOT_RC" -ne 0 ]; then
    log_critical "Branch-hotspot probe failed with rc=$BRANCH_HOTSPOT_RC"
fi
if [ "$BRANCH_HOTSPOTS" -gt 5 ]; then
    log_warning "High branching hotspot count (>=80 if/match tokens per function): $BRANCH_HOTSPOTS"
else
    log_info "Branching hotspot count acceptable: $BRANCH_HOTSPOTS"
fi

# Thread Safety Audit
echo -e "\n+===============================================================+"
echo "|                 THREAD SAFETY AUDIT                            |"
echo "+===============================================================+"

echo -e "\n> Checking for race conditions..."
STATIC_MUT_LOG="$OUTPUT_DIR/static-mut-scan.log"
set +e
STATIC_MUT_LOCATIONS="$(rg -n --no-heading "static mut" src -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' 2>"$STATIC_MUT_LOG")"
STATIC_MUT_RC=$?
set -e
record_search_check "static_mut_scan" "$STATIC_MUT_RC" "artifact=$STATIC_MUT_LOG"
if [ "$STATIC_MUT_RC" -gt 1 ]; then
    log_critical "static mut scan failed with rc=$STATIC_MUT_RC"
fi
split_locations_with_allowlist "static_mut" "$STATIC_MUT_LOCATIONS"
STATIC_MUT=$(printf "%s\n" "$BLOCKER_LOCATIONS" | sed '/^$/d' | count_lines)
STATIC_MUT_TOLERATED=$(printf "%s\n" "$TOLERATED_LOCATIONS" | sed '/^$/d' | count_lines)
if [ "$STATIC_MUT" -gt 0 ]; then
    log_critical "Found $STATIC_MUT static mut variables (race condition risk)"
fi
if [ "$STATIC_MUT_TOLERATED" -gt 0 ]; then
    log_info "Tolerated static mut occurrences (allowlisted): $STATIC_MUT_TOLERATED"
fi

echo -e "\n> Analyzing synchronization primitives..."
MUTEX_COUNT=$(grep -r "Mutex\|RwLock" src/ --include="*.rs" | wc -l)
ATOMIC_COUNT=$(grep -r "Atomic" src/ --include="*.rs" | wc -l)
log_info "Synchronization: $MUTEX_COUNT mutexes/locks, $ATOMIC_COUNT atomics"

# Crypto Audit
echo -e "\n+===============================================================+"
echo "|                   CRYPTO AUDIT                                 |"
echo "+===============================================================+"

echo -e "\n> Checking for weak crypto..."
WEAK_CRYPTO_LOG="$OUTPUT_DIR/weak-crypto-scan.log"
set +e
WEAK_CRYPTO_MATCHES="$(
    rg -n --no-heading -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' -i \
      -e '\b(md5|sha1|rc4)::' \
      -e '\b(Md5|Sha1|Rc4)\b' \
      src/crypto src/transport src/stealth 2>"$WEAK_CRYPTO_LOG"
)"
WEAK_CRYPTO_RC=$?
set -e
record_search_check "weak_crypto_scan" "$WEAK_CRYPTO_RC" "artifact=$WEAK_CRYPTO_LOG"
if [ "$WEAK_CRYPTO_RC" -gt 1 ]; then
    log_critical "Weak-crypto scan failed with rc=$WEAK_CRYPTO_RC"
fi
WEAK_CRYPTO=$(printf "%s\n" "$WEAK_CRYPTO_MATCHES" | sed '/^$/d' | count_lines)
if [ "$WEAK_CRYPTO" -gt 0 ]; then
    log_critical "Weak cryptographic algorithms detected: $WEAK_CRYPTO occurrences"
    printf "%s\n" "$WEAK_CRYPTO_MATCHES" | head -3 | tee -a "$AUDIT_LOG" || true
fi

echo -e "\n> Checking constant-time operations..."
CT_VIOLATIONS=$(( $( (grep -rE "if.*secret|if.*key|if.*password" src/crypto/ --include="*.rs" 2>/dev/null || true) | wc -l | tr -d '[:space:]' ) + 0 ))
if [ "$CT_VIOLATIONS" -gt 0 ]; then
    log_warning "Potential timing attacks: $CT_VIOLATIONS conditional branches on secrets"
fi

qf_json_append_object "$JSON" \
  "name=audit_metric_scope" "status=PASS" "result=METRIC_SCOPE_DECLARED" \
  "unsafe_scope=parsed-rust-production-files-with-test-config-exclusion" \
  "leak_scope=parsed-rust-production-files-with-test-config-exclusion" \
  "secret_scope=tracked-executable-and-configuration-surfaces-with-explicit-generated-test-fixture-exclusions" \
  "quality_scope=raw-source-heuristics-not-executed-behavior-proof" \
  "timing_scope=raw-conditional-token-matches-under-src-crypto" \
  "commented_code_scope=raw-comment-pattern-matches-under-src-excluding-test-directories" \
  "test_metric_scope=source-marker-presence-not-executed-coverage"

# Generate Report
echo -e "\n+===============================================================+"
echo "|                    AUDIT SUMMARY                               |"
echo "+===============================================================+"

TOTAL_ISSUES=$((CRITICAL_ISSUES + WARNINGS_FOUND))
echo -e "\n  Critical Issues:  $CRITICAL_ISSUES"
echo "  Warnings:         $WARNINGS_FOUND"
echo "  Total Issues:     $TOTAL_ISSUES"
echo "  Check failures:   $CHECK_FAILURES"
echo "  Unavailable:      $CHECK_UNAVAILABLE"
echo "  Mode:             $MODE"
echo "  Audit Log:        $AUDIT_LOG"

AUDIT_CONTRACT_LOG="$OUTPUT_DIR/audit-result-contract.json"
set +e
python3 "$SCRIPT_DIR/audit-result-contract.py" \
  --mode "$MODE" \
  --critical "$CRITICAL_ISSUES" \
  --check-failures "$CHECK_FAILURES" \
  --unavailable "$CHECK_UNAVAILABLE" \
  --warnings "$WARNINGS_FOUND" >"$AUDIT_CONTRACT_LOG" 2>&1
AUDIT_CONTRACT_RC=$?
set -e

AUDIT_STATUS="FAIL"
CONTRACT_BLOCKING="true"
CONTRACT_EXIT_CODE=1
CONTRACT_PARSE_RC=1
if [[ "$AUDIT_CONTRACT_RC" -eq 0 || "$AUDIT_CONTRACT_RC" -eq 1 ]]; then
    set +e
    AUDIT_CONTRACT_VALUES=$(python3 - "$AUDIT_CONTRACT_LOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("schema") != "quicfuscate.audit-result-contract.v1":
    raise SystemExit("unexpected audit result contract schema")
print(report["status"], str(report["blocking"]).lower(), report["exit_code"])
PY
    )
    CONTRACT_PARSE_RC=$?
    set -e
fi
if [[ "$CONTRACT_PARSE_RC" -eq 0 ]]; then
    read -r AUDIT_STATUS CONTRACT_BLOCKING CONTRACT_EXIT_CODE <<<"$AUDIT_CONTRACT_VALUES"
    qf_json_append_object "$JSON" \
      "name=audit_result_contract" "status=PASS" \
      "contract_status=$AUDIT_STATUS" "blocking=json:$CONTRACT_BLOCKING" \
      "exit_code=int:$CONTRACT_EXIT_CODE" "command_rc=int:$AUDIT_CONTRACT_RC" \
      "evidence=$AUDIT_CONTRACT_LOG"
else
    record_check "audit_result_contract" FAIL "$AUDIT_CONTRACT_RC" "artifact=$AUDIT_CONTRACT_LOG"
    log_critical "Audit result contract could not be parsed"
fi

qf_json_append_object "$JSON" \
  "name=audit_summary" "status=$AUDIT_STATUS" "mode=$MODE" \
  "critical_issues=int:$CRITICAL_ISSUES" "warnings=int:$WARNINGS_FOUND" \
  "check_failures=int:$CHECK_FAILURES" "unavailable_checks=int:$CHECK_UNAVAILABLE" \
  "result_contract_artifact=$AUDIT_CONTRACT_LOG"
json_end "$JSON"

if [ "$AUDIT_STATUS" != "PASS" ]; then
    if [ "$STRICT" -eq 1 ] || [ "$CONTRACT_PARSE_RC" -ne 0 ]; then
        echo -e "\n${RED}[FAIL] AUDIT FAILED - status=$AUDIT_STATUS (strict mode)${NC}"
        exit 1
    fi
    echo -e "\n${YELLOW}[WARN]  AUDIT COMPLETED WITH NON-PASS STATUS=$AUDIT_STATUS (advisory mode)${NC}"
    exit 0
elif [ "$WARNINGS_FOUND" -gt 20 ]; then
    echo -e "\n${YELLOW}[WARN]  AUDIT PASSED WITH WARNINGS - Consider addressing warnings${NC}"
    exit 0
else
    echo -e "\n${GREEN}[OK] AUDIT PASSED - Code quality acceptable${NC}"
    exit 0
fi
