#!/usr/bin/env bash
# Description: Verify ALL profiles against their .sha256 sidecars

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

if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
if command -v shasum >/dev/null 2>&1; then HASH='shasum -a 256'; else HASH=sha256sum; fi
failed=0; total=0
for d in browser_profiles src/browser_profiles; do
  [ -d "$d" ] || continue
  for f in "$d"/*.chlo; do
    [ -e "$f" ] || continue
    total=$((total+1))
    s=${f%.chlo}.sha256
    base=$(basename "$f"); name=${base%.chlo}; browser=${name%%_*}; os=${name#*_}
    if [ ! -f "$s" ]; then echo " - ${browser^}/${os^}: [MISS] sidecar $s"; failed=$((failed+1)); continue; fi
    got=$(base64 $DEC < "$f" | $HASH | awk '{print $1}')
    exp=$(tr -d '\n\r' < "$s")
    if [ "$got" = "$exp" ]; then echo " - ${browser^}/${os^}: [ OK ]"; else echo " - ${browser^}/${os^}: [FAIL] mismatch"; echo "    expected: $exp"; echo "         got: $got"; failed=$((failed+1)); fi
  done
done
echo "[E2E] Summary: total=$total failed=$failed"
[ "$failed" -eq 0 ]
