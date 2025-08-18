#!/usr/bin/env bash
# Description: List TLS profiles

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1

echo 'Scanning for ClientHello profiles...'
found=0
for d in browser_profiles src/browser_profiles; do
  if [ -d "$d" ]; then
    echo "[dir] $d"
    for f in "$d"/*.chlo; do
      [ -e "$f" ] || continue
      base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
      echo " - ${browser^}/${os^}"
      found=1
    done
  fi
done
if [ "$found" = 0 ]; then echo 'No .chlo profiles found in browser_profiles/ or src/browser_profiles/.'; fi
