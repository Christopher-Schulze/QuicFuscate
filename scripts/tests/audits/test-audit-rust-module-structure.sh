#!/usr/bin/env bash
# Description: Exercise Rust module structure size and include! failure paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VALIDATOR="$SCRIPT_DIR/audit-rust-module-structure.sh"
FIXTURES="$SCRIPT_DIR/fixtures/rust-module-structure"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-rust-module-structure.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

case "${1:-}" in
  "") ;;
  -h|--help|help)
    printf '%s\n' "Usage: $(basename "$0")"
    exit 0
    ;;
  *)
    printf 'Unknown argument: %s\n' "$1" >&2
    exit 2
    ;;
esac

copy_fixture() {
  local name="$1"
  rm -rf "$TEMP_ROOT/repo"
  mkdir -p "$TEMP_ROOT/repo/src"
  cp "$FIXTURES/$name.rs" "$TEMP_ROOT/repo/src/lib.rs"
}

expect_pass() {
  local output
  output="$(QF_AUDIT_PROJECT_ROOT="$TEMP_ROOT/repo" QF_RUST_MODULE_MAX_LINES=5 "$VALIDATOR" 2>&1)" || {
    printf 'expected module structure validator pass, got:\n%s\n' "$output" >&2
    return 1
  }
  [[ "$output" == *"PASS: Rust module structure"* ]]
}

expect_fail() {
  local expected="$1"
  local output
  if output="$(QF_AUDIT_PROJECT_ROOT="$TEMP_ROOT/repo" QF_RUST_MODULE_MAX_LINES=5 "$VALIDATOR" 2>&1)"; then
    printf 'expected module structure validator failure containing %s\n' "$expected" >&2
    return 1
  fi
  [[ "$output" == *"$expected"* ]] || {
    printf 'expected failure %s, got:\n%s\n' "$expected" "$output" >&2
    return 1
  }
}

copy_fixture pass
expect_pass

copy_fixture oversized
expect_fail 'OVERSIZED: src/lib.rs lines=6 limit=5'

copy_fixture textual-assembly
expect_fail 'TEXTUAL_ASSEMBLY: src/lib.rs:2 uses include!'

copy_fixture comment-only
expect_pass

if QF_AUDIT_PROJECT_ROOT="$TEMP_ROOT/repo" QF_RUST_MODULE_MAX_LINES=zero "$VALIDATOR" >/dev/null 2>&1; then
  printf '%s\n' 'expected invalid line limit to fail' >&2
  exit 1
fi

printf '%s\n' 'PASS: Rust module structure validator fixtures'
