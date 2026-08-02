#!/usr/bin/env bash
# Description: Analyze shell scripts for consistency (shebang/strict mode/description/help).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: missing required command: rg" >&2
  exit 2
fi

OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help|help)
      cat <<'EOF'
Usage: analysis-scripts-quality.sh [--output-dir DIR]

Scans scripts/*.sh (excluding scripts/out/*) and reports:
- missing shebang
- missing strict mode (set -euo pipefail / -Eeuo pipefail)
- missing # Description:
- missing help handler tokens (-h|--help|help)
- naming scheme violations (category prefix + kebab-case)
- scripts with help handlers but no "Usage:" line
- non-standard unknown-arg handling (must be stderr + exit 2)
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUT_DIR" ]] && OUT_DIR="$PROJECT_ROOT/scripts/out/analysis/scripts-quality-$TS"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/report.txt"
JSON="$OUT_DIR/results.json"
json_begin "$JSON" "analysis_scripts_quality"
JSON_FIRST_RUN=1

total=0
missing_shebang=0
missing_strict=0
missing_desc=0
missing_help=0
invalid_name=0
missing_usage_line=0
bad_unknown_arg=0

NAME_SCHEME='^(audit|analysis|bench|build|fast|install|lib|micro|smoke|test|util|wrap)-[a-z0-9-]+\.sh$'

{
  echo "Scripts Quality Report ($TS)"
  echo "Root: $PROJECT_ROOT"
  echo
} > "$REPORT"

while IFS= read -r f; do
  total=$((total + 1))
  rel="${f#$PROJECT_ROOT/}"
  base="$(basename "$f")"
  is_lib=0
  [[ "$rel" == "scripts/tests/lib/lib-common.sh" ]] && is_lib=1

  head1="$(head -n 1 "$f" 2>/dev/null || true)"
  if [[ ! "$head1" =~ ^#! ]]; then
    echo "MISSING_SHEBANG $rel" >> "$REPORT"
    missing_shebang=$((missing_shebang + 1))
  fi

  if [[ "$is_lib" -eq 0 ]]; then
    if ! rg -q "set -([Ee]{1,2}uo|euo) pipefail" "$f"; then
      echo "MISSING_STRICT $rel" >> "$REPORT"
      missing_strict=$((missing_strict + 1))
    fi
  fi

  if ! rg -q "^# Description:" "$f"; then
    echo "MISSING_DESC $rel" >> "$REPORT"
    missing_desc=$((missing_desc + 1))
  fi

  if [[ "$is_lib" -eq 0 ]] && ! rg -q -- "-h\\|--help|--help|-h|help" "$f"; then
    echo "MISSING_HELP_HANDLER $rel" >> "$REPORT"
    missing_help=$((missing_help + 1))
  fi

  if [[ "$is_lib" -eq 0 ]]; then
    has_help=0
    rg -q -- "-h\\|--help|--help|-h|help" "$f" && has_help=1
    if [[ "$has_help" -eq 1 ]] && ! rg -q 'Usage:' "$f"; then
      echo "MISSING_USAGE_LINE $rel" >> "$REPORT"
      missing_usage_line=$((missing_usage_line + 1))
    fi
  fi

  if [[ ! "$base" =~ $NAME_SCHEME ]]; then
    echo "INVALID_NAME $rel" >> "$REPORT"
    invalid_name=$((invalid_name + 1))
  fi

  if [[ "$is_lib" -eq 0 ]]; then
    if rg -q 'Unknown (flag|argument):|unknown argument:|Unknown arg:' "$f"; then
      if ! rg -q '>&2' "$f" || ! rg -q 'exit 2' "$f"; then
        echo "BAD_UNKNOWN_ARG_HANDLING $rel" >> "$REPORT"
        bad_unknown_arg=$((bad_unknown_arg + 1))
      fi
    fi
  fi
done < <(find "$PROJECT_ROOT/scripts" -path "$PROJECT_ROOT/scripts/out" -prune -o -name '*.sh' -print | sort)

cat >> "$REPORT" <<EOF

Summary:
  total=$total
  missing_shebang=$missing_shebang
  missing_strict=$missing_strict
  missing_desc=$missing_desc
  missing_help=$missing_help
  invalid_name=$invalid_name
  missing_usage_line=$missing_usage_line
  bad_unknown_arg=$bad_unknown_arg
EOF

qf_json_append_object "$JSON" \
  "total=int:$total" "missing_shebang=int:$missing_shebang" \
  "missing_strict=int:$missing_strict" "missing_desc=int:$missing_desc" \
  "missing_help=int:$missing_help" "invalid_name=int:$invalid_name" \
  "missing_usage_line=int:$missing_usage_line" "bad_unknown_arg=int:$bad_unknown_arg"
json_end "$JSON"

echo "report: $REPORT"
echo "json:   $JSON"
