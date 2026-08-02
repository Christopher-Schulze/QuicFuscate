#!/usr/bin/env bash
# Description: Diff TLS profiles (env A vs B)
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_diff_profiles"; JSON_FIRST_RUN=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"; cd "$ROOT" || exit 1

A=${QUICFUSCATE_DIFF_A:-}
B=${QUICFUSCATE_DIFF_B:-}
if [ -z "$B" ]; then echo 'Set QUICFUSCATE_DIFF_B=browser_os (e.g., firefox_linux)'; exit 2; fi
if [ -z "$A" ]; then
  B1=${QUICFUSCATE_BROWSER:-Chrome}
  O1=${QUICFUSCATE_OS:-Windows}
  A=$(echo "$B1" | tr 'A-Z' 'a-z')_$(echo "$O1" | tr 'A-Z' 'a-z')
fi
A_b=${A%%_*}; A_o=${A#*_}
B_b=${B%%_*}; B_o=${B#*_}

# Resolve files
set_base64_decode_flag DEC
set_sha256_cmd HASH

find_profile() {
  local name="$1"; local out=""
  for d in browser_profiles; do [ -d "$d" ] || continue
    f="$d/${name}.chlo"; [ -f "$f" ] && { echo "$f"; return; }
  done
  echo ""
}

FA=$(find_profile "$A")
FB=$(find_profile "$B")
if [ -z "$FA" ] || [ -z "$FB" ]; then
  echo "Profile(s) not found: A=$A (file=$FA), B=$B (file=$FB)"; exit 3
fi

shaA=$(base64 $DEC < "$FA" | $HASH | awk '{print $1}')
shaB=$(base64 $DEC < "$FB" | $HASH | awk '{print $1}')
equal=0; [ "$shaA" = "$shaB" ] && equal=1

qf_json_append_object "$JSON" \
  "A=$A" "B=$B" "fileA=$FA" "fileB=$FB" \
  "shaA=$shaA" "shaB=$shaB" "equal=int:$equal"

tmpA="$OUTPUT_DIR/${BASE_NAME}.tmpA.bin"
tmpB="$OUTPUT_DIR/${BASE_NAME}.tmpB.bin"
rm -f "$tmpA" "$tmpB"
foundA=0; foundB=0
for d in browser_profiles; do
  f="$d/${A_b}_${A_o}.chlo"
  if [ -f "$f" ]; then base64 $DEC < "$f" > "$tmpA"; foundA=1; break; fi
done
for d in browser_profiles; do
  f="$d/${B_b}_${B_o}.chlo"
  if [ -f "$f" ]; then base64 $DEC < "$f" > "$tmpB"; foundB=1; break; fi
done
if [ "$foundA" = 0 ] || [ "$foundB" = 0 ]; then echo 'Profile(s) not found.'; rm -f "$tmpA" "$tmpB"; exit 3; fi

echo "[A] $A  size=$(wc -c < "$tmpA")"
echo "[B] $B  size=$(wc -c < "$tmpB")"
if cmp -s "$tmpA" "$tmpB"; then
  echo 'Profiles identical.'
else
  echo 'Profiles differ.'
  cmp -l "$tmpA" "$tmpB" | head -n 10 || true
fi
hexdump -C -n 64 "$tmpA" | sed 's/^/[A] /'
hexdump -C -n 64 "$tmpB" | sed 's/^/[B] /'
rm -f "$tmpA" "$tmpB"
json_end "$JSON"
