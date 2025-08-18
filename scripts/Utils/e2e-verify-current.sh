#!/usr/bin/env bash
# Description: Verify current profile against its .sha256 sidecar

set -e

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
if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
if command -v shasum >/dev/null 2>&1; then HASH='shasum -a 256'; else HASH=sha256sum; fi
found=0
for d in browser_profiles src/browser_profiles; do
  f="$d/${b}_${o}.chlo"; s="$d/${b}_${o}.sha256"
  if [ -f "$f" ]; then
    found=1
    if [ ! -f "$s" ]; then echo "[E2E] VERIFY FAIL: missing sidecar $s"; exit 1; fi
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
if [ "$found" = 0 ]; then echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/ or src/browser_profiles/."; exit 3; fi
