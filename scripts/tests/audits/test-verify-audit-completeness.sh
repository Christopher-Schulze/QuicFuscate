#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR="$SCRIPT_DIR/verify-audit-completeness.sh"
BASE_FIXTURE="$SCRIPT_DIR/fixtures/audit-completeness/base"
VARIANT_DIR="$SCRIPT_DIR/fixtures/audit-completeness/variants"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-audit-completeness.XXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT

copy_fixture() {
    rm -rf "$TEMP_ROOT/repo"
    cp -R "$BASE_FIXTURE" "$TEMP_ROOT/repo"
    git -C "$TEMP_ROOT/repo" init -q
    git -C "$TEMP_ROOT/repo" config user.email "audit-fixture@example.invalid"
    git -C "$TEMP_ROOT/repo" config user.name "Audit Fixture"
    git -C "$TEMP_ROOT/repo" add .
    git -C "$TEMP_ROOT/repo" commit -q -m "fixture"
}

run_validator() {
    QF_AUDIT_PROJECT_ROOT="$TEMP_ROOT/repo" "$VALIDATOR"
}

expect_pass() {
    local output
    output="$(run_validator 2>&1)" || {
        printf 'expected validator pass, got:\n%s\n' "$output" >&2
        return 1
    }
    [[ "$output" == *"PASS: audit completeness"* ]]
}

expect_fail() {
    local expected="$1"
    local output
    if output="$(run_validator 2>&1)"; then
        printf 'expected validator failure containing %s\n' "$expected" >&2
        return 1
    fi
    [[ "$output" == *"$expected"* ]] || {
        printf 'expected failure %s, got:\n%s\n' "$expected" "$output" >&2
        return 1
    }
}

copy_fixture
expect_pass

cp "$VARIANT_DIR/malformed-section.md" "$TEMP_ROOT/repo/docs/todo.md"
expect_fail "unexpected tracker section 'Paused'"

copy_fixture
cp "$VARIANT_DIR/duplicate-id.md" "$TEMP_ROOT/repo/docs/todo.md"
expect_fail "duplicate tracker ID TODO-1"

copy_fixture
cp "$VARIANT_DIR/missing-detail.md" "$TEMP_ROOT/repo/docs/todo.md"
expect_fail "TODO-3 has 0 canonical Detail lines"

copy_fixture
cp "$VARIANT_DIR/status-mismatch.md" "$TEMP_ROOT/repo/docs/todo.md"
cp "$VARIANT_DIR/status-mismatch-todo-2.md" "$TEMP_ROOT/repo/docs/todo/todo-2-blocked.md"
expect_fail "Blocked tracker entry TODO-2 has status OPEN"

printf '%s\n' 'PASS: audit completeness validator fixtures'
