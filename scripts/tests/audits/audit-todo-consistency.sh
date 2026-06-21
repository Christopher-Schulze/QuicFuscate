#!/usr/bin/env bash
# Description: Audit TODO system consistency — validates YAML frontmatter
# in docs/todo/todo-*.md and cross-checks against docs/todo.md master index.
#
# Checks:
#   1. Every docs/todo/todo-*.md has YAML frontmatter with a status: field.
#   2. Every status: value is one of: OPEN, DONE, DEFERRED, SCRAP.
#   3. The status in each detail file matches the status in docs/todo.md.
#
# Exit codes:
#   0 — all checks pass
#   1 — one or more violations found
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--verbose]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TS="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TS}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

VALID_STATUSES="OPEN DONE DEFERRED SCRAP"
violations=0
total_files=0

echo "=== TODO Consistency Audit ==="
echo "Project root: $PROJECT_ROOT"
echo "Timestamp: $TS"
echo

# --- Check 1 & 2: YAML frontmatter + valid status in detail files ---
echo "--- Check 1 & 2: YAML frontmatter + valid status ---"

declare -A DETAIL_STATUS_MAP

for f in docs/todo/todo-*.md; do
  [[ -f "$f" ]] || continue
  total_files=$((total_files + 1))

  # Extract YAML frontmatter (between first pair of ---)
  frontmatter=$(awk '/^---$/{n++; if(n==2) exit} n==1' "$f" 2>/dev/null)

  if [[ -z "$frontmatter" ]]; then
    echo "VIOLATION: $f — no YAML frontmatter found"
    violations=$((violations + 1))
    continue
  fi

  # Extract status field
  status=$(echo "$frontmatter" | grep -E '^status:' | sed 's/^status:[[:space:]]*//' | tr -d '"' | tr -d "'")

  if [[ -z "$status" ]]; then
    echo "VIOLATION: $f — no status: field in YAML frontmatter"
    violations=$((violations + 1))
    continue
  fi

  # Validate status value
  valid=0
  for v in $VALID_STATUSES; do
    if [[ "$status" == "$v" ]]; then
      valid=1
      break
    fi
  done

  if [[ $valid -eq 0 ]]; then
    echo "VIOLATION: $f — invalid status value '$status' (must be one of: $VALID_STATUSES)"
    violations=$((violations + 1))
    continue
  fi

  # Extract TODO ID from filename
  basename "$f" | grep -oE 'todo-[0-9]+' | grep -oE '[0-9]+' > /dev/null 2>&1
  todo_id=$(basename "$f" | grep -oE 'todo-[0-9]+' | grep -oE '[0-9]+')
  if [[ -n "$todo_id" ]]; then
    DETAIL_STATUS_MAP["TODO-$todo_id"]="$status"
  fi
done

echo "Detail files scanned: $total_files"
echo

# --- Check 3: Cross-check against todo.md master index ---
echo "--- Check 3: Cross-check detail files vs docs/todo.md ---"

TODO_MD="docs/todo.md"
if [[ ! -f "$TODO_MD" ]]; then
  echo "VIOLATION: $TODO_MD not found"
  violations=$((violations + 1))
else
  # Extract TODO-XXX and **STATUS** from table rows in todo.md
  # Pattern: | TODO-XXX | ... | **STATUS** |
  while IFS= read -r line; do
    # Extract TODO ID
    todo_id=$(echo "$line" | grep -oE 'TODO-[0-9]+' | head -1)
    [[ -z "$todo_id" ]] && continue

    # Extract status from **STATUS** pattern
    md_status=$(echo "$line" | grep -oE '\*\*[A-Z]+\*\*' | head -1 | tr -d '*')

    [[ -z "$md_status" ]] && continue

    # Check if we have a detail file for this ID
    detail_status="${DETAIL_STATUS_MAP[$todo_id]:-}"

    if [[ -z "$detail_status" ]]; then
      # No detail file — skip (some old TODOs only exist in todo.md)
      continue
    fi

    if [[ "$detail_status" != "$md_status" ]]; then
      echo "VIOLATION: $todo_id — todo.md says '$md_status' but detail file says '$detail_status'"
      violations=$((violations + 1))
    fi
  done < <(grep -E '^\|.*TODO-[0-9]+.*\*\*[A-Z]+\*\*' "$TODO_MD")
fi

echo
echo "=== Summary ==="
echo "Total detail files: $total_files"
echo "Total violations:   $violations"
echo

if [[ $violations -gt 0 ]]; then
  echo "RESULT: FAIL — $violations violation(s) found"
  exit 1
else
  echo "RESULT: PASS — all TODO files are consistent"
  exit 0
fi
