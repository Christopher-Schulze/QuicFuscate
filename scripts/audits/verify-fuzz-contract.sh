#!/usr/bin/env bash
# Verify the source-owned fuzz manifest, target inventory, corpus, and CI contracts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz"
CI_WORKFLOW="$PROJECT_ROOT/.github/workflows/ci.yml"
SCHEDULED_WORKFLOW="$PROJECT_ROOT/.github/workflows/fuzz-scheduled.yml"
SEEDS_IGNORE="/scripts/tests/fuzz/seeds/"

readonly TARGETS=(
  connection_handling
  crypto_operations
  fec_encoding
  frame_decoding
  packet_parsing
  varint_parsing
)

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

[[ -f "$FUZZ_DIR/Cargo.toml" ]] || fail "fuzz manifest is missing"
grep -Fq 'quicfuscate = { path = "../../..", features = ["rust-tests"] }' "$FUZZ_DIR/Cargo.toml" \
  || fail "fuzz manifest must resolve the repository root crate"
grep -Fq '/scripts/tests/fuzz/corpus/' "$PROJECT_ROOT/.gitignore" \
  || fail "runtime fuzz corpus must remain ignored"
grep -Fq '/scripts/tests/fuzz/artifacts/' "$PROJECT_ROOT/.gitignore" \
  || fail "fuzz crash artifacts must remain ignored"
if grep -Fq "$SEEDS_IGNORE" "$PROJECT_ROOT/.gitignore"; then
  fail "the retained curated seed corpus must not be ignored"
fi

cargo +nightly metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --no-deps --format-version 1 --locked >/dev/null \
  || fail "cargo metadata cannot resolve the fuzz workspace"
command -v cargo-fuzz >/dev/null 2>&1 || fail "cargo-fuzz is required for target discovery"
expected_targets="$(printf '%s\n' "${TARGETS[@]}" | sort)"
actual_targets="$(cargo +nightly fuzz list --fuzz-dir "$FUZZ_DIR" | sort)"
[[ "$actual_targets" == "$expected_targets" ]] || fail "cargo-fuzz target inventory differs from the six declared targets"

for target in "${TARGETS[@]}"; do
  target_source="$FUZZ_DIR/fuzz_targets/$target.rs"
  [[ -f "$target_source" ]] || fail "missing fuzz target source: $target"
  count="$(git -C "$PROJECT_ROOT" ls-files "scripts/tests/fuzz/seeds/$target/*" | wc -l | tr -d ' ')"
  (( count > 0 && count <= 8 )) || fail "$target seed corpus must contain 1..8 tracked curated files (found $count)"
done

grep -Fq "github.event_name == 'pull_request'" "$CI_WORKFLOW" \
  || fail "PR fuzz lane is missing from ci.yml"
grep -Fq "github.event_name == 'push'" "$CI_WORKFLOW" \
  || fail "main-push fuzz lane is missing from ci.yml"
for workflow in "$CI_WORKFLOW" "$SCHEDULED_WORKFLOW"; do
  grep -Fq 'cargo +nightly install cargo-fuzz --version "0.13.2" --locked' "$workflow" \
    || fail "$(basename "$workflow") must install cargo-fuzz with explicit nightly"
  grep -Fq 'RUSTFLAGS="-Zsanitizer=address" bash scripts/tests/fuzz/run-ci-fuzz.sh' "$workflow" \
    || fail "$(basename "$workflow") must scope AddressSanitizer to the fuzz runner"
done
grep -Fq 'scripts/tests/fuzz/run-ci-fuzz.sh' "$CI_WORKFLOW" \
  || fail "ci.yml must call the shared fuzz runner"
[[ -f "$SCHEDULED_WORKFLOW" ]] || fail "scheduled fuzz workflow is missing"
grep -Fq 'schedule:' "$SCHEDULED_WORKFLOW" || fail "scheduled fuzz workflow has no schedule trigger"
grep -Fq 'scripts/tests/fuzz/run-ci-fuzz.sh' "$SCHEDULED_WORKFLOW" \
  || fail "scheduled workflow must call the shared fuzz runner"
grep -Fq 'actions/upload-artifact@v7' "$CI_WORKFLOW" \
  || fail "ci.yml must upload fuzz artifacts"
grep -Fq 'actions/upload-artifact@v7' "$SCHEDULED_WORKFLOW" \
  || fail "scheduled fuzz workflow must upload fuzz artifacts"

CRYPTO_TARGET="$FUZZ_DIR/fuzz_targets/crypto_operations.rs"
grep -Fq 'PUBLIC_FORCE_AEAD_VALUES' "$CRYPTO_TARGET" \
  || fail "crypto fuzz target lacks the public AEAD value inventory"
grep -Fq 'INTERNAL_AEGIS_BACKEND_VALUES' "$CRYPTO_TARGET" \
  || fail "crypto fuzz target lacks the internal backend inventory"
for value in auto aegis-128l aegis128l aegis morus morus-1280-128 morus1280-128 aegis-128x4 aegis-128x8; do
  grep -Fq "\"$value\"" "$CRYPTO_TARGET" || fail "crypto fuzz target does not cover $value"
done

echo "[PASS] fuzz manifest, target inventory, curated seeds, CI lanes, sanitizer, artifacts, and crypto contract are aligned"
