#!/usr/bin/env bash
# Description: Verify ALL profiles against their .sha256 sidecars
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_e2e_verify_all"; JSON_FIRST_RUN=1
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

set_base64_decode_flag DEC
set_sha256_cmd HASH
failed=0; total=0
for d in browser_profiles; do
  [ -d "$d" ] || continue
  for f in "$d"/*.chlo; do
    [ -e "$f" ] || continue
    total=$((total+1))
    sidecar_rel="${d}/$(basename "${f%.chlo}.sha256")"
    s_legacy="${f%.chlo}.sha256"
    s_snapshot=""
    s="$s_legacy"
    if [[ -n "$SIDECARS_DIR" ]]; then
      s_snapshot="${SIDECARS_DIR}/${sidecar_rel}"
      if [[ -f "$s_snapshot" ]]; then
        s="$s_snapshot"
      fi
    fi
    base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
    if [ ! -f "$s" ]; then
      if [[ -n "$SIDECARS_DIR" ]]; then
        echo " - ${browser^}/${os^}: [MISS] sidecar ${s_snapshot:-$s_legacy} (fallback ${s_legacy})"
      else
        echo " - ${browser^}/${os^}: [MISS] sidecar $s_legacy"
      fi
      failed=$((failed+1))
      continue
    fi
    got=$(base64 $DEC < "$f" | $HASH | awk '{print $1}')
    exp=$(tr -d '\n\r' < "$s")
    if [ "$got" = "$exp" ]; then echo " - ${browser^}/${os^}: [ OK ]"; else echo " - ${browser^}/${os^}: [FAIL] mismatch"; echo "    expected: $exp"; echo "         got: $got"; failed=$((failed+1)); fi
  done
done
echo "[E2E] Summary: total=$total failed=$failed"
[ "$failed" -eq 0 ]
qf_json_append_object "$JSON" "total=int:$total" "failed=int:$failed"
json_end "$JSON"
