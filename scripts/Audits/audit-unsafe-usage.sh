#!/usr/bin/env bash
# Description: Unsafe usage scanner

# Preserve original behavior (no strict mode)

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

if command -v cargo-geiger >/dev/null 2>&1; then
  cargo geiger
else
  echo '[fallback] grep for unsafe blocks:'
  grep -RIn --exclude-dir=target --exclude-dir=.git --exclude-dir=_fec_backup* '\\bunsafe[[:space:]]*{' src 2>/dev/null || echo 'No unsafe blocks found (grep)'
fi
