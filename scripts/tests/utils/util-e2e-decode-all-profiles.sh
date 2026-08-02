#!/usr/bin/env bash
# Description: Decode ALL profiles
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
require_base64_tool

SCRIPT_NAME="$(basename "$0")"
DESC="$(grep -m1 '^# Description:' "$0" | sed 's/^# Description:[[:space:]]*//')"
print_help() { echo "Usage: $SCRIPT_NAME"; [ -n "$DESC" ] && echo "$DESC"; exit 0; }

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) print_help;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/utils/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_e2e_decode_profiles"; JSON_FIRST_RUN=1

find_repo_root() {
  local d
  d="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
  while [ "$d" != "/" ]; do
    if [ -f "$d/Cargo.toml" ]; then echo "$d"; return; fi
    d="$(dirname "$d")"
  done
  echo "."
}
ROOT="$(find_repo_root)"; cd "$ROOT" || exit 1

echo '[E2E] Decoding all ClientHello profiles'
if [ ! -d "browser_profiles" ]; then
  echo 'NOTE: browser_profiles/ directory does not exist. TLS fingerprints are generated in-memory.'
  echo '      External .chlo dumps are optional auditing artifacts. Skipping decode.'
fi
set_base64_decode_flag DEC
found=0
for d in browser_profiles; do
  [ -d "$d" ] || continue
  for f in "$d"/*.chlo; do
    [ -e "$f" ] || continue
    base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
    size=$(base64 $DEC < "$f" | wc -c | tr -d ' ')
    printf ' - %-10s/%-10s | %6d bytes | head(32B): ' "${browser^}" "${os^}" "$size"
    base64 $DEC < "$f" | dd bs=1 count=32 2>/dev/null | hexdump -v -e '16/1 "%02x"' | sed 's/..../& /g'
    echo
    found=1
    # JSON item
    qf_json_append_object "$JSON" \
      "browser=${browser^}" "os=${os^}" "dir=$d" "file=$base" \
      "decoded_size=int:$size"
  done
done
if [ "$found" = 0 ]; then echo 'No .chlo profiles found.'; fi
json_end "$JSON"
