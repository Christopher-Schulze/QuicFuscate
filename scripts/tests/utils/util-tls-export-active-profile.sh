#!/usr/bin/env bash
# Description: Export active TLS profile
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
require_base64_and_sha256_tools

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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_export_profile"; JSON_FIRST_RUN=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"; cd "$ROOT" || exit 1

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
b=$(echo "$B" | tr 'A-Z' 'a-z')
o=$(echo "$O" | tr 'A-Z' 'a-z')

set_base64_decode_flag DEC
set_sha256_cmd HASH
found=0
profile_dir=""
profile_file=""
export_out=""
export_meta=""
for d in browser_profiles; do [ -d "$d" ] || continue
  f="$d/${b}_${o}.chlo"
  if [ -f "$f" ]; then
    found=1
    profile_dir="$d"
    profile_file="$f"
    mkdir -p "$OUTPUT_DIR/profiles"
    TS=$(date +%Y%m%d_%H%M%S)
    export_out="$OUTPUT_DIR/profiles/${b}_${o}_${TS}.bin"
    export_meta="$OUTPUT_DIR/profiles/${b}_${o}_${TS}.meta.json"
    base64 $DEC < "$f" > "$export_out"
    sz=$(wc -c < "$export_out" | tr -d ' ')
    sum=$($HASH "$export_out" | awk '{print $1}')
    qf_json_write_object_file "$export_meta" \
      "browser=$B" "os=$O" "file=$export_out" "size=int:$sz" \
      "sha256=$sum" "timestamp=$(date -u +%FT%TZ)"
    echo "[export] $export_out"
    echo "[meta]   $export_meta"
    break
  fi
done
if [ "$found" = 0 ]; then
  echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/."
  json_end "$JSON"
  exit 3
fi
size_dec=$(base64 $DEC < "$profile_file" | wc -c | tr -d ' ')
qf_json_append_object "$JSON" \
  "browser=$B" "os=$O" "dir=$profile_dir" "file=$(basename "$profile_file")" \
  "decoded_size=int:$size_dec" "exported_bin=$export_out" "exported_meta=$export_meta"
json_end "$JSON"
