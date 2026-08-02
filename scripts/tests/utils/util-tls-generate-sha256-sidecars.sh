#!/usr/bin/env bash
# Description: Generate .sha256 sidecars for TLS profiles
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
# JSON header
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_generate_sidecars"; JSON_FIRST_RUN=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"; cd "$ROOT" || exit 1

set_base64_decode_flag DEC
set_sha256_cmd HASH

gen() {
  dir=$1
  [ -d "$dir" ] || return 0
  echo "[gen] $dir"
  sidecar_dir="$OUTPUT_DIR/sidecars/$dir"
  mkdir -p "$sidecar_dir"
  while read -r f; do
    got=$(base64 $DEC < "$f" | $HASH | awk '{print $1}')
    base=$(basename "$f")
    sidecar_file="$sidecar_dir/${base%.chlo}.sha256"
    echo "$got" > "$sidecar_file"
    # JSON item per generated sidecar
    name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
    size_dec=$(base64 $DEC < "$f" | wc -c | tr -d ' ')
    qf_json_append_object "$JSON" \
      "browser=${browser^}" "os=${os^}" "dir=$dir" "file=$base" \
      "decoded_size=int:$size_dec" "sha256=$got" "sidecar=$sidecar_file"
  done < <(find "$dir" -name '*.chlo' -type f)
}

gen browser_profiles

echo '[gen] done.'
json_end "$JSON"
