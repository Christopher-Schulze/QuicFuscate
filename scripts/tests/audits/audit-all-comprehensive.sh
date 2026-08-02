#!/usr/bin/env bash
# Description: Audit runner: audit-all-comprehensive.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
ALLOWLIST_FILE="$SCRIPT_DIR/allowlists/critical-allowlist.txt"

OUTPUT_DIR=""
STRICT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --strict) STRICT=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Comprehensive Security & Quality Audit"; usage_common_flags 2>/dev/null || true; exit 0;;
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "audit_all"; JSON_FIRST_RUN=1

ISSUES_FOUND=0
WARNINGS_FOUND=0
CRITICAL_ISSUES=0

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
UNSAFE_COUNT=$(grep -r "unsafe" src/ --include="*.rs" | wc -l)
UNSAFE_IN_PROD=$(grep -r "unsafe" src/ --include="*.rs" | grep -v "test" | grep -v "bench" | wc -l)
if [ "$UNSAFE_IN_PROD" -gt 50 ]; then
    log_warning "High unsafe usage in production code: $UNSAFE_IN_PROD blocks"
else
    log_info "Unsafe usage acceptable: $UNSAFE_IN_PROD blocks in production"
fi

echo -e "\n> Checking for panic-inducing code..."
STRICT_RUNTIME_CLIPPY="$OUTPUT_DIR/strict-runtime-clippy.log"
set +e
RUNTIME_CLIPPY_OUTPUT=$(cargo clippy --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic 2>&1)
RUNTIME_CLIPPY_RC=$?
set -e
printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" > "$STRICT_RUNTIME_CLIPPY"

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
SECRET_ASSIGN_RE='(password|secret|token|api[_-]?key|private[_-]?key|credential)[[:space:]]*[:=][[:space:]]*"[^"]{8,}"'
SECRET_KEY_BLOCK_RE='-----BEGIN[[:space:]]+(RSA|EC|OPENSSH|PRIVATE)[[:space:]]+PRIVATE[[:space:]]+KEY-----'
SECRET_MATCHES="$( (rg -n --no-heading -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' -g '!src/implementations/server/parts/tests_inline.rs' -e "$SECRET_ASSIGN_RE" -e "$SECRET_KEY_BLOCK_RE" src || true) )"
SECRET_COUNT=$(printf "%s\n" "$SECRET_MATCHES" | sed '/^$/d' | count_lines)
if [ "$SECRET_COUNT" -gt 0 ]; then
    log_critical "Hardcoded secret literals detected: $SECRET_COUNT occurrences"
    printf "%s\n" "$SECRET_MATCHES" | head -3 | tee -a "$AUDIT_LOG" || true
else
    log_info "No hardcoded secrets detected"
fi

echo -e "\n> Checking memory safety..."
LEAK_PATTERNS="mem::forget|Box::leak|ManuallyDrop"
LEAK_COUNT=$( (grep -rE "$LEAK_PATTERNS" src/ --include="*.rs" | grep -v "test" || true) | wc -l)
if [ "$LEAK_COUNT" -gt 0 ]; then
    log_warning "Potential memory leaks: $LEAK_COUNT patterns found"
fi

# Dependency Audit
echo -e "\n+===============================================================+"
echo "|                  DEPENDENCY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Checking for vulnerable dependencies..."
if command -v cargo-audit &> /dev/null; then
    set +e
    AUDIT_OUTPUT=$(cargo audit 2>&1)
    AUDIT_RC=$?
    set -e
    if [ "$AUDIT_RC" -ne 0 ]; then
        log_critical "cargo audit command failed with rc=$AUDIT_RC"
    fi
    VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Vulnerability" || true)
    if [ "$VULN_COUNT" -gt 0 ]; then
        log_critical "Found $VULN_COUNT vulnerable dependencies"
        echo "$AUDIT_OUTPUT" | grep "Vulnerability" | head -5 | tee -a "$AUDIT_LOG" || true
    else
        log_info "No known vulnerabilities in dependencies"
    fi
else
    log_warning "cargo-audit not installed, skipping vulnerability check"
fi

echo -e "\n> Checking dependency licenses..."
TOTAL_DEPS=$(cargo tree --no-dedupe 2>/dev/null | wc -l)
log_info "Total dependencies: $TOTAL_DEPS"

# Performance Audit
echo -e "\n+===============================================================+"
echo "|                 PERFORMANCE AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing hot path optimizations..."
INLINE_ALWAYS=$(grep -r "#\[inline(always)\]" src/ --include="*.rs" | wc -l)
INLINE_REGULAR=$(grep -r "#\[inline\]" src/ --include="*.rs" | grep -v "inline(always)" | wc -l)
log_info "Inline annotations: $INLINE_ALWAYS always, $INLINE_REGULAR regular"

echo -e "\n> Checking for performance anti-patterns..."
CLONE_LINT_LOG="$OUTPUT_DIR/clone-lints.log"
CLONE_LINT_OUTPUT=$(cargo clippy --lib --bins --all-features -- -W clippy::redundant_clone -W clippy::clone_on_copy -W clippy::iter_cloned_collect 2>&1 || true)
printf "%s\n" "$CLONE_LINT_OUTPUT" > "$CLONE_LINT_LOG"
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

echo -e "\n> Checking allocations in hot paths..."
HOT_PATH_ALLOCS=$(
python3 - <<'PY'
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
COMMENTED_CODE_LOCATIONS="$(rg -n --no-heading -e "$COMMENTED_CODE_RE" src -g '*.rs' -g '!**/tests/**' || true)"
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
MISSING_DOCS=$(echo "$DOC_OUTPUT" | grep -c "missing documentation" || true)
if [ "$DOC_RC" -ne 0 ]; then
    log_critical "cargo doc command failed with rc=$DOC_RC"
elif [ "$MISSING_DOCS" -gt 20 ]; then
    log_warning "Poor documentation: $MISSING_DOCS items missing docs"
else
    log_info "Documentation coverage good: $MISSING_DOCS items missing"
fi

echo -e "\n> Checking test coverage..."
TEST_FILES=$(find src -name "*.rs" -exec grep -l "#\[test\]" {} \; | wc -l)
TOTAL_FILES=$(find src -name "*.rs" | wc -l)
TEST_COVERAGE=$((TEST_FILES * 100 / TOTAL_FILES))
if [ "$TEST_COVERAGE" -lt 30 ]; then
    log_warning "Low test coverage: only $TEST_COVERAGE% of files have tests"
else
    log_info "Test coverage acceptable: $TEST_COVERAGE% of files"
fi
qf_json_append_object "$JSON" \
  "unsafe_in_prod=int:$UNSAFE_IN_PROD" "unwrap_calls=int:$UNWRAP_COUNT" \
  "panic_macros=int:$PANIC_COUNT" "secrets=int:$SECRET_COUNT" \
  "leak_patterns=int:$LEAK_COUNT" "simd_features=int:$SIMD_FEATURES" \
  "test_coverage_percent=int:$TEST_COVERAGE"

echo -e "\n> Running runtime guardrails..."
if "$SCRIPT_DIR/audit-runtime-guardrails.sh" --output-dir "$OUTPUT_DIR/runtime-guardrails"; then
    log_info "Runtime guardrails passed"
else
    log_critical "Runtime guardrails failed (see $OUTPUT_DIR/runtime-guardrails)"
fi

# Complexity Audit
echo -e "\n+===============================================================+"
echo "|                  COMPLEXITY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing function complexity..."
LONG_FUNCTIONS=$(
python3 - <<'PY'
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
if [ "$LONG_FUNCTIONS" -gt 35 ]; then
    log_warning "Many very long functions (>=300 lines): $LONG_FUNCTIONS"
else
    log_info "Very long function count acceptable: $LONG_FUNCTIONS"
fi

echo -e "\n> Checking cyclomatic complexity..."
BRANCH_HOTSPOTS=$(
python3 - <<'PY'
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
STATIC_MUT_LOCATIONS="$(rg -n --no-heading "static mut" src -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' || true)"
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
WEAK_CRYPTO_MATCHES="$(
  (
    rg -n --no-heading -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' -i \
      -e '\b(md5|sha1|rc4)::' \
      -e '\b(Md5|Sha1|Rc4)\b' \
      src/crypto src/transport src/stealth 2>/dev/null || true
  )
)"
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

# Generate Report
echo -e "\n+===============================================================+"
echo "|                    AUDIT SUMMARY                               |"
echo "+===============================================================+"

TOTAL_ISSUES=$((CRITICAL_ISSUES + WARNINGS_FOUND))

echo -e "\n  Critical Issues:  $CRITICAL_ISSUES"
echo "  Warnings:         $WARNINGS_FOUND"
echo "  Total Issues:     $TOTAL_ISSUES"
echo "  Audit Log:        $AUDIT_LOG"

json_end "$JSON"

if [ "$CRITICAL_ISSUES" -gt 0 ]; then
    if [ "$STRICT" -eq 1 ]; then
        echo -e "\n${RED}[FAIL] AUDIT FAILED - Critical issues must be resolved (strict mode)${NC}"
        exit 1
    fi
    echo -e "\n${YELLOW}[WARN]  AUDIT COMPLETED WITH CRITICAL FINDINGS (advisory mode, use --strict to fail)${NC}"
    exit 0
elif [ "$WARNINGS_FOUND" -gt 20 ]; then
    echo -e "\n${YELLOW}[WARN]  AUDIT PASSED WITH WARNINGS - Consider addressing warnings${NC}"
    exit 0
else
    echo -e "\n${GREEN}[OK] AUDIT PASSED - Code quality acceptable${NC}"
    exit 0
fi
