#!/usr/bin/env bash
# Description: Show current TLS/Stealth env overrides that map into StealthConfig.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

# Unified help handler
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_tls_show_active_env"; JSON_FIRST_RUN=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"; cd "$ROOT" || exit 1

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
F=${QUICFUSCATE_USE_TLS_COVER:-0}
D=${QUICFUSCATE_DOH:-1}
FP=${QUICFUSCATE_DOH_PROVIDER:-https://cloudflare-dns.com/dns-query}
FR=${QUICFUSCATE_FRONTING:-1}
Q=${QUICFUSCATE_QPACK:-1}

qf_json_append_object "$JSON" \
  "browser=$B" "os=$O" "use_tls_cover=$F" "doh_enabled=$D" \
  "doh_provider=$FP" "fronting=$FR" "qpack=$Q"

json_end "$JSON"

echo 'Active TLS/Stealth configuration (env overrides -> StealthConfig):'
printf ' - Browser: %q\n' "$B"
printf ' - OS: %q\n' "$O"
printf ' - Use TLS Cover: %q\n' "$F"
printf ' - DoH enabled: %q\n' "$D"
printf ' - DoH provider: %q\n' "$FP"
printf ' - Domain fronting: %q\n' "$FR"
printf ' - QPACK headers: %q\n' "$Q"
echo
echo 'Tip: export QUICFUSCATE_BROWSER/QUICFUSCATE_OS to change the uTLS fingerprint.'
