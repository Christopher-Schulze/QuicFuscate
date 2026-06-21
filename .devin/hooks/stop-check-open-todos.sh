#!/bin/bash
# Stop-Hook: Prevents agent from stopping while actionable TODOs remain.
# Also drives optimization loop after all TODOs are done.
#
# Logic:
#   1. Open+unsuperseded TODOs exist → BLOCK (agent must continue)
#   2. No open TODOs, but git progress since last block → BLOCK (run optimization)
#   3. No open TODOs, no git progress since last block → ALLOW stop (exhausted)
#
# State file tracks last commit hash to detect progress.

cd "$DEVIN_PROJECT_DIR" 2>/dev/null || exit 0

STATE_FILE="/tmp/devin-stop-hook-state-$(basename "$DEVIN_PROJECT_DIR")"
LAST_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "none")
PREV_COMMIT=$(cat "$STATE_FILE" 2>/dev/null || echo "init")

# --- Count open, non-superseded TODOs ---
open_count=0
open_list=""
for f in docs/todo/todo-*.md; do
  [ -f "$f" ] || continue
  if grep -q '^status: OPEN' "$f" 2>/dev/null && ! grep -q '^superseded_by:' "$f" 2>/dev/null; then
    open_count=$((open_count + 1))
    id=$(grep '^id:' "$f" | head -1 | sed 's/^id: //')
    title=$(grep '^title:' "$f" | head -1 | sed 's/^title: //' | sed 's/"//g' | cut -c1-60)
    open_list="${open_list}${id}: ${title}; "
  fi
done

# --- Case 1: Open TODOs remain → BLOCK ---
if [ $open_count -gt 0 ]; then
  echo "$LAST_COMMIT" > "$STATE_FILE"
  # Truncate list if too long
  if [ ${#open_list} -gt 400 ]; then
    open_list="${open_list:0:400}..."
  fi
  cat << EOF
{"decision": "block", "reason": "Open TODOs remain (${open_count}): ${open_list} Continue: find next OPEN TODO in docs/todo/ (highest priority P0>P1>P2, depends_on satisfied), read its detail file, implement fully, test, commit (NO Devin co-author), push, set status: DONE in the .md file, update docs/todo.md. Then continue with the next."}
EOF
  exit 0
fi

# --- Case 2: No open TODOs, check if agent made progress ---
if [ "$LAST_COMMIT" = "$PREV_COMMIT" ]; then
  # No progress since last block → agent is stuck/exhausted → ALLOW stop
  rm -f "$STATE_FILE"
  exit 0
fi

# --- Case 3: No open TODOs but progress was made → BLOCK for optimization ---
echo "$LAST_COMMIT" > "$STATE_FILE"
cat << 'EOF'
{"decision": "block", "reason": "All TODOs done. Enter optimization loop: (1) du -sh . — if >10GB run cargo clean, (2) cargo test --lib, (3) cargo clippy --all-targets -- -D warnings, (4) review code for unnecessary allocations, clone reduction, SIMD opportunities, lock contention, (5) if improvements found: implement, test, commit, push. (6) If nothing found after thorough review, you may stop."}
EOF
