#!/usr/bin/env bash
# Description: Build quiche and check

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
if [ -d libs/patched_quiche ]; then
  pushd libs/patched_quiche >/dev/null
  if [ -f Cargo.toml ]; then
    echo '[quiche] Building patched quiche (release)...'
    cargo build --release
  elif [ -f Makefile ]; then
    echo '[quiche] Building via Makefile...'
    make
  else
    echo '[quiche] No Cargo.toml or Makefile; please add build instructions.'
  fi
  popd >/dev/null
  echo '[quiche] Build done.'
fi

echo '[root] cargo check'
cargo check
