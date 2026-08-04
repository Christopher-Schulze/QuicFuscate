#!/usr/bin/env bash
# Description: Analysis helper: analysis-dead-code-report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

# Flags
OUTPUT_DIR=""; QUICFUSCATE_DEBUG_SCRIPTS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) export QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--dry-run] [--verbose]"; exit 0;;
    *) break;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "analysis_dead_code"
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"

count_lines() {
  local pattern="$1"
  shift
  (rg --no-messages -- "$pattern" "$@" || true) | wc -l | tr -d '[:space:]'
}

count_lines_in_file() {
  local pattern="$1"
  local file="$2"
  (rg --no-messages -- "$pattern" "$file" || true) | wc -l | tr -d '[:space:]'
}

echo "==============================================================="
echo "  Dead Code Analysis Report"
echo "==============================================================="
echo "  Analyzing unused code across the entire codebase"
echo "==============================================================="

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Statistics
total_dead_code=0

echo -e "\n${YELLOW}=== Dead Code Markers by Module ===${NC}"

while IFS= read -r -d '' file; do
    basename="${file#src/}"
    count=$(count_lines_in_file '#\[allow\(dead_code\)\]' "$file")
    total_dead_code=$((total_dead_code + count))

    if (( count > 0 )); then
        echo -e "  ${basename}: ${RED}${count}${NC} dead code markers"
        echo -e "    ${BLUE}Items:${NC}"
        (rg --no-messages -B 1 '#\[allow\(dead_code\)\]' "$file" || true) |
            (rg --no-messages '^(pub )?(fn |struct |enum |const |static |type |trait |impl )' || true) |
            sed 's/^/      - /' | head -10

        if (( count > 10 )); then
            echo "      ... and $((count - 10)) more"
        fi
    else
        echo -e "  ${basename}: ${GREEN}0${NC} dead code markers"
    fi
done < <(find src -name '*.rs' -type f -print0 | sort -z)

echo -e "\n${YELLOW}=== Unused Functions Analysis ===${NC}"
echo "Searching for potentially unused private functions..."

while IFS= read -r -d '' file; do
    basename="${file#src/}"
    echo -e "\n  ${BLUE}${basename}:${NC}"

    private_fns=$( (rg --no-messages '^[[:space:]]*fn [a-z_][a-z0-9_]*\(' "$file" || true) |
                  (rg --no-messages -v '^[[:space:]]*pub' || true) |
                  sed 's/.*fn \([a-z_][a-z0-9_]*\).*/\1/' |
                  sort -u)

    if [[ -z "$private_fns" ]]; then
        echo "    No private functions found"
        continue
    fi

    while IFS= read -r fn_name; do
        [[ -n "$fn_name" ]] || continue
        usage_count=$(count_lines_in_file "\\b${fn_name}\\(" "$file")
        if (( usage_count > 0 )); then
            usage_count=$((usage_count - 1))
        fi

        if (( usage_count == 0 )); then
            echo -e "    ${RED}[WARN]${NC} $fn_name: appears unused"
        elif (( usage_count == 1 )); then
            echo -e "    ${YELLOW}?${NC} $fn_name: used only once"
        fi
    done <<< "$private_fns"
done < <(find src -name '*.rs' -type f -print0 | sort -z)

echo -e "\n${YELLOW}=== Unused Structs/Enums Analysis ===${NC}"

while IFS= read -r -d '' file; do
    basename="${file#src/}"
    echo -e "\n  ${BLUE}${basename}:${NC}"

    private_types=$( (rg --no-messages '^[[:space:]]*(struct|enum) [A-Z][A-Za-z0-9_]*' "$file" || true) |
                    (rg --no-messages -v '^[[:space:]]*pub' || true) |
                    awk '
                        {
                            for (i = 1; i <= NF; i++) {
                                if ($i == "struct" || $i == "enum") {
                                    n = $(i + 1);
                                    sub(/[^A-Za-z0-9_].*$/, "", n);
                                    if (n ~ /^[A-Z]/) print n;
                                }
                            }
                        }
                    ' |
                    sort -u)

    if [[ -z "$private_types" ]]; then
        echo "    No private types found"
        continue
    fi

    while IFS= read -r type_name; do
        [[ -n "$type_name" ]] || continue
        usage_count=$( (rg --no-messages --glob '*.rs' -F -- "$type_name" src/ || true) |
                      awk -v t="$type_name" '$0 !~ "struct " t && $0 !~ "enum " t' |
                      wc -l | tr -d '[:space:]')

        if (( usage_count == 0 )); then
            echo -e "    ${RED}[WARN]${NC} $type_name: appears unused"
        elif (( usage_count <= 2 )); then
            echo -e "    ${YELLOW}?${NC} $type_name: minimal usage ($usage_count references)"
        fi
    done <<< "$private_types"
done < <(find src -name '*.rs' -type f -print0 | sort -z)

echo -e "\n${YELLOW}=== Feature-Gated Code Analysis ===${NC}"
echo "Checking feature-gated code blocks..."

feature_gates=$( (rg --no-messages --no-filename '#\[cfg\(' src/ --glob '*.rs' || true) |
                sed 's/.*#\[cfg(\([^)]*\)).*/\1/' |
                sort -u)

if [[ -n "$feature_gates" ]]; then
    echo "Found feature gates:"
    while IFS= read -r gate; do
        [[ -n "$gate" ]] || continue
        count=$( (rg --no-messages --no-filename -F "#[cfg(${gate}" src/ --glob '*.rs' || true) | wc -l | tr -d '[:space:]')
        echo -e "  ${BLUE}$gate${NC}: $count occurrences"
    done <<< "$feature_gates"
else
    echo "No feature gates found"
fi

echo -e "\n${YELLOW}=== TODO/FIXME/HACK Comments ===${NC}"

for marker in "TODO" "FIXME" "HACK" "XXX" "STUB"; do
    count=$(count_lines "$marker" src/ --glob '*.rs')
    if (( count > 0 )); then
        echo -e "  ${YELLOW}$marker${NC}: $count occurrences"
        (rg --no-messages "$marker" src/ --glob '*.rs' || true) | head -3 | sed 's/^/    /'
        if (( count > 3 )); then
            echo "    ... and $((count - 3)) more"
        fi
    fi
done

echo -e "\n${YELLOW}=== Unused Dependencies Check ===${NC}"
echo "Analyzing Cargo.toml dependencies..."

deps=$(awk '
  /^\[[^]]*dependencies[^]]*\][[:space:]]*$/ {
    in_dependencies = 1
    next
  }
  /^\[/ {
    in_dependencies = 0
    next
  }
  in_dependencies && /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
    name = $0
    sub(/[[:space:]]*=.*/, "", name)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
    print name
  }
' Cargo.toml | sort -u)

for dep in $deps; do
    usage=$(count_lines "use $dep|extern crate $dep|$dep::" src/ --glob '*.rs')

    if (( usage == 0 )); then
        usage=$(count_lines "\\b$dep\\b" src/ --glob '*.rs')
        if (( usage == 0 )); then
            echo -e "  ${RED}[WARN]${NC} $dep: appears unused"
        elif (( usage <= 2 )); then
            echo -e "  ${YELLOW}?${NC} $dep: minimal usage"
        fi
    fi
done

echo -e "\n${YELLOW}=== Summary ===${NC}"
echo -e "  Total dead code markers: ${RED}$total_dead_code${NC}"
echo -e "  Modules with most dead code:"

while IFS= read -r -d '' file; do
    count=$(count_lines_in_file '#\[allow\(dead_code\)\]' "$file")
    if (( count > 0 )); then
        echo "$count ${file#src/}"
    fi
done < <(find src -name '*.rs' -type f -print0 | sort -z) | sort -rn | head -5 | while read -r count file; do
    [[ -n "${count:-}" && -n "${file:-}" ]] || continue
    echo -e "    ${RED}$count${NC} in $file"
done

echo -e "\n${YELLOW}=== Recommendations ===${NC}"
echo "1. Review items marked with #[allow(dead_code)] - they may be removable"
echo "2. Consider removing or implementing stub functions"
echo "3. Check if feature-gated code is still needed"
echo "4. Review TODO/FIXME comments for unfinished work"
echo "5. Audit dependencies for actual usage"

echo -e "\n${RED}[WARN] WARNING:${NC} Do NOT automatically remove dead code!"
echo "Some code may be:"
echo "  - Used by tests or benchmarks"
echo "  - Required for future features"
echo "  - Platform-specific implementations"
echo "  - Public API that external users depend on"

echo -e "\n${GREEN}[OK] Dead Code Analysis Complete${NC}"
qf_json_append_object "$JSON" "total_dead_code_markers=int:$total_dead_code"
qf_json_append_object "$JSON" "name=analysis_summary" "status=PASS" "result=REPORT" "total_dead_code_markers=int:$total_dead_code"
json_end "$JSON"
