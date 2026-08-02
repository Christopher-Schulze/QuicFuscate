#!/usr/bin/env bash
# Description: Curate fuzz seed corpora (dedupe per target).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
require_sha256_tool
set_sha256_cmd HASH

SEEDS_DIR="$PROJECT_ROOT/scripts/tests/fuzz/seeds"
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seeds-dir) SEEDS_DIR="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x; shift ;;
    -h|--help|help)
      cat <<'EOF'
Usage: util-fuzz-seed-curate.sh [--seeds-dir DIR] [--output-dir DIR] [--dry-run]

Deduplicates fuzz seed files per target directory by SHA-256 content.
Default seeds dir: scripts/tests/fuzz/seeds
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/utils/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_fuzz_seed_curate"; JSON_FIRST_RUN=1

if [[ ! -d "$SEEDS_DIR" ]]; then
  echo "Seeds directory not found: $SEEDS_DIR" >&2
  json_end "$JSON"
  exit 2
fi

total_files=0
total_removed=0
total_kept=0

echo "[curate] seeds dir: $SEEDS_DIR"
echo "[curate] mode: ${DRY_RUN:+dry-run}${DRY_RUN:-apply}"

for target_dir in "$SEEDS_DIR"/*; do
  [[ -d "$target_dir" ]] || continue
  target_name="$(basename "$target_dir")"
  index_file="$OUTPUT_DIR/${target_name}.sha256.idx"
  : > "$index_file"

  scanned=0
  removed=0
  kept=0

  while IFS= read -r seed_file; do
    [[ -f "$seed_file" ]] || continue
    scanned=$((scanned + 1))
    total_files=$((total_files + 1))
    digest=$($HASH "$seed_file" | awk '{print $1}')

    if awk -v h="$digest" '$1==h{found=1} END{exit !found}' "$index_file"; then
      removed=$((removed + 1))
      total_removed=$((total_removed + 1))
      if [[ -z "${DRY_RUN:-}" ]]; then
        find "$seed_file" -type f -delete
      fi
    else
      echo "$digest $seed_file" >> "$index_file"
      kept=$((kept + 1))
      total_kept=$((total_kept + 1))
    fi
  done < <(find "$target_dir" -type f | sort)

  echo "[curate] $target_name: scanned=$scanned kept=$kept removed=$removed"
  qf_json_append_object "$JSON" "target=$target_name" "scanned=int:$scanned" \
    "kept=int:$kept" "removed=int:$removed"
done

echo "[curate] total: scanned=$total_files kept=$total_kept removed=$total_removed"
json_end "$JSON"
