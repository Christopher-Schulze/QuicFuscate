#!/usr/bin/env bash
# Description: Generate .sha256 sidecars for TLS profiles

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1

if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi
if command -v shasum >/dev/null 2>&1; then HASH='shasum -a 256'; else HASH=sha256sum; fi

gen() {
  dir=$1
  [ -d "$dir" ] || return 0
  echo "[gen] $dir"
  find "$dir" -name '*.chlo' -type f | while read -r f; do
    got=$(base64 $DEC < "$f" | $HASH | awk '{print $1}')
    echo "$got" > "${f%.chlo}.sha256"
  done
}

gen browser_profiles

gen src/browser_profiles

echo '[gen] done.'
