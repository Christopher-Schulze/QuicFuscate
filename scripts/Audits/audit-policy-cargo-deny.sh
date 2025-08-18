#!/usr/bin/env bash
# Description: License/Policy audit using cargo-deny

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

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check bans licenses advisories
else
  echo 'cargo-deny not installed. Install: cargo install cargo-deny'
fi
