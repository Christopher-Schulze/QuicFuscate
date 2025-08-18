#!/usr/bin/env bash
# Description: Export active TLS profile

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
b=$(echo "$B" | tr 'A-Z' 'a-z')
o=$(echo "$O" | tr 'A-Z' 'a-z')

if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
found=0
for d in browser_profiles src/browser_profiles; do
  f="$d/${b}_${o}.chlo"
  if [ -f "$f" ]; then
    found=1
    mkdir -p artifacts/profiles
    TS=$(date +%Y%m%d_%H%M%S)
    out=artifacts/profiles/${b}_${o}_${TS}.bin
    meta=artifacts/profiles/${b}_${o}_${TS}.meta.json
    base64 $DEC < "$f" > "$out"
    if command -v shasum >/dev/null 2>&1; then HASH='shasum -a 256'; else HASH=sha256sum; fi
    sz=$(wc -c < "$out" | tr -d ' ')
    sum=$($HASH "$out" | awk '{print $1}')
    printf '{"browser":%q,"os":%q,"file":%q,"size":%s,"sha256":%q,"timestamp":%q}\n' "$B" "$O" "$out" "$sz" "$sum" "$(date -u +%FT%TZ)" > "$meta"
    echo "[export] $out"
    echo "[meta]   $meta"
    break
  fi
done
if [ "$found" = 0 ]; then echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/ or src/browser_profiles/."; exit 3; fi
