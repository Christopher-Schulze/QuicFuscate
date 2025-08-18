#!/usr/bin/env bash
# Description: All tests in release mode

# No strict mode in original; preserve behavior.

# Resolve repo root (directory containing Cargo.toml) starting from this script's location
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

cargo test --all-targets --release -- --nocapture
