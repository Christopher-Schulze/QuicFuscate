#!/usr/bin/env bash
# Description: List TLS profiles
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
# JSON header
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_list_profiles"; JSON_FIRST_RUN=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"; cd "$ROOT" || exit 1

echo 'Scanning for ClientHello profiles...'
if [ ! -d "browser_profiles" ]; then
  echo 'NOTE: browser_profiles/ directory does not exist. TLS fingerprints are generated in-memory at runtime.'
  echo '      External .chlo dumps are optional auditing artifacts only.'
fi
found=0
set_base64_decode_flag DEC
for d in browser_profiles; do
  if [ -d "$d" ]; then
    echo "[dir] $d"
    for f in "$d"/*.chlo; do
      [ -e "$f" ] || continue
      base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
      echo " - ${browser^}/${os^}"
      found=1
      size_dec=$(base64 $DEC < "$f" | wc -c | tr -d ' ')
      qf_json_append_object "$JSON" \
        "browser=${browser^}" "os=${os^}" "dir=$d" "file=$base" \
        "decoded_size=int:$size_dec"
    done
  fi
done
if [ "$found" = 0 ]; then echo 'No .chlo profiles found in browser_profiles/.'; fi
json_end "$JSON"
