#!/usr/bin/env bash
# Description: Show profile head
# Purpose: Show a short decoded hex head of the selected profile from QUICFUSCATE_BROWSER/OS

set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT_DIR"

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
b=$(echo "$B" | tr 'A-Z' 'a-z')
o=$(echo "$O" | tr 'A-Z' 'a-z')

found=0
for d in browser_profiles src/browser_profiles; do
  f="$d/${b}_${o}.chlo"
  if [ -f "$f" ]; then
    echo "Using: $f"
    if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
    echo '[decoded head]'
    base64 $DEC < "$f" | hexdump -C -n 64 || true
    found=1
    break
  fi
done

if [ "$found" = 0 ]; then
  echo "Profile file not found for ${b}_${o}.chlo in browser_profiles/ or src/browser_profiles/."
fi
