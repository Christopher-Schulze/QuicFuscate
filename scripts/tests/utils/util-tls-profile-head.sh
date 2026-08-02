#!/usr/bin/env bash
# Description: Show profile head.
set -euo pipefail

# Shows a short decoded hex head of the selected profile from QUICFUSCATE_BROWSER/OS.
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_profile_head"; JSON_FIRST_RUN=1

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd -P)"
cd "$ROOT_DIR"

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
b=$(echo "$B" | tr 'A-Z' 'a-z')
o=$(echo "$O" | tr 'A-Z' 'a-z')

found=0
set_base64_decode_flag DEC
for d in browser_profiles; do [ -d "$d" ] || continue
  f="$d/${b}_${o}.chlo"
  if [ -f "$f" ]; then
    echo "Using: $f"
    echo '[decoded head]'
    head_hex=$(base64 $DEC < "$f" | dd bs=1 count=32 2>/dev/null | hexdump -v -e '16/1 "%02x"' | sed 's/..../& /g')
    echo "$head_hex"
    size_dec=$(base64 $DEC < "$f" | wc -c | tr -d ' ')
    # JSON item
    qf_json_append_object "$JSON" \
      "browser=$B" "os=$O" "dir=$d" "file=$(basename "$f")" \
      "decoded_size=int:$size_dec" "head_hex=$head_hex"
    found=1
    break
  fi
done
json_end "$JSON"

if [ "$found" = 0 ]; then
  echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/."
fi
