#!/usr/bin/env bash
# Description: Decode ALL profiles

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

echo '[E2E] Decoding all ClientHello profiles'
if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
found=0
for d in browser_profiles src/browser_profiles; do
  [ -d "$d" ] || continue
  for f in "$d"/*.chlo; do
    [ -e "$f" ] || continue
    base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
    size=$(base64 $DEC < "$f" | wc -c | tr -d ' ')
    printf ' - %-10s/%-10s | %6d bytes | head(32B): ' "${browser^}" "${os^}" "$size"
    base64 $DEC < "$f" | dd bs=1 count=32 2>/dev/null | hexdump -v -e '16/1 "%02x"' | sed 's/..../& /g'
    echo
    found=1
  done
done
if [ "$found" = 0 ]; then echo 'No .chlo profiles found.'; fi
