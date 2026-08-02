#!/usr/bin/env bash
# Description: Verify current profile against its .sha256 sidecar
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
require_base64_and_sha256_tools

SCRIPT_NAME="$(basename "$0")"
DESC="$(grep -m1 '^# Description:' "$0" | sed 's/^# Description:[[:space:]]*//')"
print_help() { echo "Usage: $SCRIPT_NAME"; [ -n "$DESC" ] && echo "$DESC"; exit 0; }

OUTPUT_DIR=""; SIDECARS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --sidecars-dir) SIDECARS_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) print_help;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/utils/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_e2e_verify_current"; JSON_FIRST_RUN=1

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

B=${QUICFUSCATE_BROWSER:-Chrome}; O=${QUICFUSCATE_OS:-Windows}
b=$(echo "$B" | tr 'A-Z' 'a-z'); o=$(echo "$O" | tr 'A-Z' 'a-z')
set_base64_decode_flag DEC
set_sha256_cmd HASH
found=0
for d in browser_profiles; do [ -d "$d" ] || continue
  f="$d/${b}_${o}.chlo"; s_legacy="$d/${b}_${o}.sha256"; s="$s_legacy"
  if [[ -n "$SIDECARS_DIR" ]]; then
    s_snapshot="$SIDECARS_DIR/$d/${b}_${o}.sha256"
    if [[ -f "$s_snapshot" ]]; then
      s="$s_snapshot"
    fi
  fi
  if [ -f "$f" ]; then
    found=1
    if [ ! -f "$s" ]; then
      if [[ -n "$SIDECARS_DIR" ]]; then
        echo "[E2E] VERIFY FAIL: missing sidecar ${s_snapshot:-$s_legacy} (fallback ${s_legacy})"
      else
        echo "[E2E] VERIFY FAIL: missing sidecar $s_legacy"
      fi
      exit 1
    fi
    got=$(base64 $DEC < "$f" | $HASH | awk '{print $1}')
    exp=$(tr -d '\n\r' < "$s")
    if [ "$got" = "$exp" ]; then
      echo "[E2E] VERIFY OK for ${B}/${O} -> $s"
    else
      echo "[E2E] VERIFY FAIL for ${B}/${O}: mismatch"; echo " expected: $exp"; echo "      got: $got"; exit 2
    fi
    break
  fi
done
if [ "$found" = 0 ]; then echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/."; exit 3; fi
qf_json_append_object "$JSON" "browser=$B" "os=$O"
json_end "$JSON"
