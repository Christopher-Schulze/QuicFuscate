#!/usr/bin/env bash
# Description: Exercise documentation truth status, link, version, and anchor failure paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VALIDATOR="$SCRIPT_DIR/audit-documentation-truth.sh"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-documentation-truth.XXXXXX")"
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
  rm -rf "$TEMP_ROOT/repo"
  mkdir -p "$TEMP_ROOT/repo"
  cp -R "$PROJECT_ROOT/docs" "$TEMP_ROOT/repo/docs"
  cp -R "$PROJECT_ROOT/config" "$TEMP_ROOT/repo/config"
  cp "$PROJECT_ROOT/Cargo.toml" "$PROJECT_ROOT/README.md" "$PROJECT_ROOT/SECURITY.md" "$TEMP_ROOT/repo/"
  cp "$PROJECT_ROOT/docs/CONTRIBUTING.md" "$TEMP_ROOT/repo/docs/CONTRIBUTING.md"
}

run_validator() {
  QF_AUDIT_PROJECT_ROOT="$TEMP_ROOT/repo" "$VALIDATOR"
}

expect_pass() {
  local output
  output="$(run_validator 2>&1)" || {
    printf 'expected documentation validator pass, got:\n%s\n' "$output" >&2
    return 1
  }
  [[ "$output" == *"PASS: documentation truth"* ]]
}

expect_fail() {
  local expected="$1"
  local output
  if output="$(run_validator 2>&1)"; then
    printf 'expected documentation validator failure containing %s\n' "$expected" >&2
    return 1
  fi
  [[ "$output" == *"$expected"* ]] || {
    printf 'expected failure %s, got:\n%s\n' "$expected" "$output" >&2
    return 1
  }
}

copy_fixture
expect_pass

python3 - "$TEMP_ROOT/repo/docs/DOCUMENTATION.md" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = "- TODO-519 is complete:"
path.write_text(text.replace(needle, "- TODO-519 remains open: native proof is pending.\n" + needle, 1), encoding="utf-8")
PY
expect_fail "TODO-519 is DONE"

copy_fixture
python3 - "$TEMP_ROOT/repo/README.md" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
path.write_text(path.read_text(encoding="utf-8") + "\n[Broken](docs/missing.md)\n", encoding="utf-8")
PY
expect_fail "broken local link"

copy_fixture
python3 - "$TEMP_ROOT/repo/SECURITY.md" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8").replace("| 0.4.x   | Yes                |", "| 0.2.x   | Yes                |", 1)
path.write_text(text, encoding="utf-8")
PY
expect_fail "current supported line"

copy_fixture
printf '\n## High-Level Architecture and Wiring\n' >> "$TEMP_ROOT/repo/docs/MAP.md"
expect_fail "duplicate Markdown anchor #high-level-architecture-and-wiring"

printf '%s\n' 'PASS: documentation truth validator fixtures'
