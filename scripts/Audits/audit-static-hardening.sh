#!/usr/bin/env bash
# Description: Scan source for unwrap/expect, debug prints, and panic/todo markers.

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

SRC=src
echo "[HARDEN] Scanning for unwrap/expect in $SRC..."
UNWRAP=$(grep -RInE --exclude-dir='_fec_backup*' "\.unwrap\\(\\)|\.expect\\(\\)" "$SRC" 2>/dev/null || true)
if [ -n "$UNWRAP" ]; then echo '[HARDEN] Found unwrap/expect:'; echo "$UNWRAP"; else echo '[HARDEN] OK: no unwrap/expect'; fi

echo '[HARDEN] Scanning for dbg!/println!/eprintln!'
DEBUGPRINT=$(grep -RInE --exclude-dir='_fec_backup*' "\bdbg!\\(|\bprintln!\\(|\beprintln!\\(" "$SRC" 2>/dev/null || true)
if [ -n "$DEBUGPRINT" ]; then echo '[HARDEN] Found debug/print:'; echo "$DEBUGPRINT"; else echo '[HARDEN] OK: no debug/print'; fi

echo '[HARDEN] Scanning for todo!/unimplemented!/panic!'
TODOLIKE=$(grep -RInE --exclude-dir='_fec_backup*' "todo!\\(|unimplemented!\\(|panic!\\(" "$SRC" 2>/dev/null | grep -viE 'test|#[[:space:]]*should_panic' || true)
if [ -n "$TODOLIKE" ]; then echo '[HARDEN] Found potential stubs/panics:'; echo "$TODOLIKE"; else echo '[HARDEN] OK: no stubs/panics'; fi

echo '[HARDEN] Scanning for TLS FFI stub markers'
STUBS=$(grep -RInE --exclude-dir='_fec_backup*' "stub invoked" "$SRC" 2>/dev/null || true)
if [ -n "$STUBS" ]; then echo '[HARDEN] Found TLS FFI stub markers:'; echo "$STUBS"; else echo '[HARDEN] OK: no explicit stub markers'; fi

echo '[HARDEN] Static hardening audit complete.'
