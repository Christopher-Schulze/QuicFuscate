#!/usr/bin/env bash
# Description: Hermetic contract test for the macOS PF anchor installer ownership transaction.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INSTALLER="$PROJECT_ROOT/scripts/install/install-macos-pf-anchor.sh"
TMP_ROOT="$(mktemp -d /tmp/quicfuscate-pf-anchor-installer.XXXXXX)"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

PF_CONF="$TMP_ROOT/etc/pf.conf"
STATE_DIR="$TMP_ROOT/var/db/quicfuscate/pf"
STATE_FILE="$STATE_DIR/managed-anchor.state"
BACKUP_FILE="$STATE_DIR/pf.conf.before-quicfuscate"
LOCK_DIR="$STATE_DIR/.installer.lock"
ANCHOR_LINE='anchor "com.quicfuscate.killswitch" all'
BEGIN_MARKER='# BEGIN QUICFUSCATE MANAGED PF ANCHOR'
END_MARKER='# END QUICFUSCATE MANAGED PF ANCHOR'

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

assert_file_hash() {
  local expected="$1" path="$2"
  local actual
  actual="$(shasum -a 256 "$path" | awk '{ print $1 }')"
  [[ "$actual" == "$expected" ]] || fail "file changed unexpectedly: $path"
}

assert_count() {
  local expected="$1" pattern="$2" path="$3"
  local actual
  actual="$(grep -Fxc -- "$pattern" "$path" || true)"
  [[ "$actual" == "$expected" ]] \
    || fail "expected $expected exact lines '$pattern' in $path, got $actual"
}

expect_failure() {
  if "$@"; then
    fail "command unexpectedly succeeded: $*"
  fi
}

replace_first() {
  local path="$1" old="$2" new="$3"
  python3 - "$path" "$old" "$new" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
contents = path.read_text(encoding="utf-8")
if old not in contents:
    raise SystemExit(f"missing replacement target: {old!r}")
path.write_text(contents.replace(old, new, 1), encoding="utf-8")
PY
}

mkdir -p "$(dirname "$PF_CONF")"
cat >"$PF_CONF" <<'EOF'
set skip on lo0
anchor "unrelated.anchor" all
pass out all
EOF

BASE_MODE="$(stat -c '%a' "$PF_CONF" 2>/dev/null || stat -f '%Lp' "$PF_CONF")"

"$INSTALLER" install --root "$TMP_ROOT"
[[ -d "$STATE_DIR" ]] || fail "installer did not create the private state directory"
[[ -f "$STATE_FILE" && -f "$BACKUP_FILE" ]] || fail "installer did not publish state and backup"
[[ "$(stat -c '%a' "$STATE_DIR" 2>/dev/null || stat -f '%Lp' "$STATE_DIR")" == "700" ]] \
  || fail "state directory is not mode 700"
[[ "$(stat -c '%a' "$STATE_FILE" 2>/dev/null || stat -f '%Lp' "$STATE_FILE")" == "600" ]] \
  || fail "ownership state is not mode 600"
[[ "$(stat -c '%a' "$BACKUP_FILE" 2>/dev/null || stat -f '%Lp' "$BACKUP_FILE")" == "600" ]] \
  || fail "pre-install backup is not mode 600"
assert_count 1 "$BEGIN_MARKER" "$PF_CONF"
assert_count 1 "$ANCHOR_LINE" "$PF_CONF"
assert_count 1 "$END_MARKER" "$PF_CONF"
grep -Fqx 'anchor "unrelated.anchor" all' "$PF_CONF" \
  || fail "unrelated PF anchor was not preserved"
grep -Fqx 'pass out all' "$PF_CONF" \
  || fail "unrelated PF rule was not preserved"

INSTALLED_HASH="$(shasum -a 256 "$PF_CONF" | awk '{ print $1 }')"
"$INSTALLER" check --root "$TMP_ROOT"
assert_file_hash "$INSTALLED_HASH" "$PF_CONF"
"$INSTALLER" install --root "$TMP_ROOT"
assert_file_hash "$INSTALLED_HASH" "$PF_CONF"

cp -p "$PF_CONF" "$TMP_ROOT/installed.pf.conf"
replace_first "$PF_CONF" "$ANCHOR_LINE" 'anchor "com.quicfuscate.killswitch"'
MODIFIED_HASH="$(shasum -a 256 "$PF_CONF" | awk '{ print $1 }')"
expect_failure "$INSTALLER" check --root "$TMP_ROOT"
expect_failure "$INSTALLER" remove --root "$TMP_ROOT"
assert_file_hash "$MODIFIED_HASH" "$PF_CONF"
cp -p "$TMP_ROOT/installed.pf.conf" "$PF_CONF"

cp -p "$STATE_FILE" "$TMP_ROOT/installed.state"
replace_first "$STATE_FILE" 'schema=1' 'schema=999'
TAMPERED_STATE_HASH="$(shasum -a 256 "$STATE_FILE" | awk '{ print $1 }')"
expect_failure "$INSTALLER" check --root "$TMP_ROOT"
assert_file_hash "$TAMPERED_STATE_HASH" "$STATE_FILE"
cp -p "$TMP_ROOT/installed.state" "$STATE_FILE"

"$INSTALLER" remove --root "$TMP_ROOT"
assert_count 0 "$BEGIN_MARKER" "$PF_CONF"
assert_count 0 "$ANCHOR_LINE" "$PF_CONF"
assert_count 0 "$END_MARKER" "$PF_CONF"
grep -Fqx 'anchor "unrelated.anchor" all' "$PF_CONF" \
  || fail "unrelated PF anchor was removed"
grep -Fqx 'pass out all' "$PF_CONF" \
  || fail "unrelated PF rule was removed"
[[ ! -e "$STATE_FILE" && ! -e "$BACKUP_FILE" ]] \
  || fail "remove left managed ownership residue"
"$INSTALLER" remove --root "$TMP_ROOT"

cat >"$PF_CONF" <<'EOF'
set skip on lo0
anchor "com.quicfuscate.killswitch" all
anchor "unrelated.anchor" all
pass out all
EOF
FOREIGN_EXACT_HASH="$(shasum -a 256 "$PF_CONF" | awk '{ print $1 }')"
expect_failure "$INSTALLER" install --root "$TMP_ROOT"
assert_file_hash "$FOREIGN_EXACT_HASH" "$PF_CONF"

cat >"$PF_CONF" <<'EOF'
set skip on lo0
anchor "com.quicfuscate/*" all
pass out all
EOF
FOREIGN_WILDCARD_HASH="$(shasum -a 256 "$PF_CONF" | awk '{ print $1 }')"
expect_failure "$INSTALLER" install --root "$TMP_ROOT"
assert_file_hash "$FOREIGN_WILDCARD_HASH" "$PF_CONF"

cat >"$PF_CONF" <<EOF
set skip on lo0

$BEGIN_MARKER
$ANCHOR_LINE
$END_MARKER
pass out all
EOF
MARKER_ONLY_HASH="$(shasum -a 256 "$PF_CONF" | awk '{ print $1 }')"
expect_failure "$INSTALLER" check --root "$TMP_ROOT"
expect_failure "$INSTALLER" install --root "$TMP_ROOT"
assert_file_hash "$MARKER_ONLY_HASH" "$PF_CONF"

cat >"$PF_CONF" <<'EOF'
set skip on lo0
anchor "unrelated.anchor" all
pass out all
EOF
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
mkdir "$LOCK_DIR"
expect_failure "$INSTALLER" install --root "$TMP_ROOT"
rmdir "$LOCK_DIR"

cat >"$PF_CONF" <<'EOF'
set skip on lo0
anchor "unrelated.anchor" all
pass out all
EOF
ln -s "$TMP_ROOT" "$TMP_ROOT/var/db/quicfuscate/pf-symlink-target"
rm -rf "$TMP_ROOT/var/db/quicfuscate/pf"
ln -s "$TMP_ROOT/var/db/quicfuscate/pf-symlink-target" "$STATE_DIR"
expect_failure "$INSTALLER" check --root "$TMP_ROOT"
expect_failure "$INSTALLER" remove --root "$TMP_ROOT"

[[ "$BASE_MODE" == "$(stat -c '%a' "$PF_CONF" 2>/dev/null || stat -f '%Lp' "$PF_CONF")" ]] \
  || fail "fixture pf.conf mode changed"

printf '[PASS] macOS PF anchor installer contract: ownership, idempotence, foreign-anchor refusal, marker integrity, lock exclusion, cleanup, and symlink rejection\n'
