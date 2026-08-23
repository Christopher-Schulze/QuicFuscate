#!/usr/bin/env bash
# Verify the source-owned fuzz manifest, target inventory, corpus, and CI contracts on the
# stable toolchain. The previous nightly-only `cargo-fuzz` + AddressSanitizer contract is gone;
# this audit enforces the stable deterministic lane instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz"
QF_CRYPTO_MANIFEST="$PROJECT_ROOT/crates/qf-crypto/Cargo.toml"
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
grep -Fqx 'log = "0.4"' "$QF_CRYPTO_MANIFEST" \
  || fail "qf-crypto must declare its direct logging dependency"
grep -Fq 'quicfuscate = { path = "../../..", features = ["rust-tests"] }' "$FUZZ_DIR/Cargo.toml" \
  || fail "fuzz manifest must resolve the repository root crate"
grep -Fq '/scripts/tests/fuzz/corpus/' "$PROJECT_ROOT/.gitignore" \
  || fail "runtime fuzz corpus must remain ignored"
grep -Fq '/scripts/tests/fuzz/artifacts/' "$PROJECT_ROOT/.gitignore" \
  || fail "fuzz crash artifacts must remain ignored"
if grep -Fq "$SEEDS_IGNORE" "$PROJECT_ROOT/.gitignore"; then
  fail "the retained curated seed corpus must not be ignored"
fi

# The fuzz crate must not depend on libfuzzer-sys on the stable lane.
grep -Fq 'libfuzzer-sys' "$FUZZ_DIR/Cargo.toml" \
  && fail "fuzz manifest must not depend on libfuzzer-sys on the stable lane" || true
# And it must not declare the cargo-fuzz metadata flag.
grep -Fq 'cargo-fuzz = true' "$FUZZ_DIR/Cargo.toml" \
  && fail "fuzz manifest must not declare cargo-fuzz metadata on the stable lane" || true

# Manifest must stay resolvable on the stable toolchain without network access.
cargo metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --format-version 1 --locked >/dev/null \
  || fail "cargo metadata cannot resolve the fuzz workspace"

# The target inventory is now read from the source-owned `src/targets.rs` module manifest.
expected_targets="$(printf '%s\n' "${TARGETS[@]}" | sort)"
actual_targets="$(sed -n 's/^pub mod \([a-z_0-9]*\);$/\1/p' "$FUZZ_DIR/src/targets.rs" | sort)"
[[ "$actual_targets" == "$expected_targets" ]] \
  || fail "fuzz target inventory differs from the six declared targets"

for target in "${TARGETS[@]}"; do
  target_source="$FUZZ_DIR/src/targets/$target.rs"
  [[ -f "$target_source" ]] || fail "missing fuzz target source: $target"
  grep -Fq 'pub fn exercise' "$target_source" \
    || fail "$target must expose a stable `pub fn exercise(&[u8])` entry point"
  # No target may keep the nightly-only libfuzzer entry machinery.
  grep -Fq 'fuzz_target!' "$target_source" \
    && fail "$target must not keep the libfuzzer `fuzz_target!` macro" || true
  grep -Fq '#![no_main]' "$target_source" \
    && fail "$target must not keep the `#![no_main]` attribute" || true
  count="$(git -C "$PROJECT_ROOT" ls-files "scripts/tests/fuzz/seeds/$target/*" | wc -l | tr -d ' ')"
  (( count > 0 && count <= 8 )) || fail "$target seed corpus must contain 1..8 tracked curated files (found $count)"
done

grep -Fq "github.event_name == 'pull_request'" "$CI_WORKFLOW" \
  || fail "PR fuzz lane is missing from ci.yml"
grep -Fq -- 'on:' "$CI_WORKFLOW" \
  || fail "ci.yml must declare a trigger surface"
for workflow in "$CI_WORKFLOW" "$SCHEDULED_WORKFLOW"; do
  grep -Fq 'scripts/tests/fuzz/run-ci-fuzz.sh' "$workflow" \
    || fail "$(basename "$workflow") must call the shared fuzz runner"
  # No workflow may install cargo-fuzz or pin the nightly toolchain on the stable lane.
  grep -Fq 'cargo +nightly install cargo-fuzz' "$workflow" \
    && fail "$(basename "$workflow") must not install cargo-fuzz on the stable lane" || true
  grep -Fq 'dtolnay/rust-toolchain@nightly' "$workflow" \
    && fail "$(basename "$workflow") must not pin the nightly toolchain on the stable lane" || true
  grep -Fq -- '-Zsanitizer=address' "$workflow" \
    && fail "$(basename "$workflow") must not scope AddressSanitizer on the stable lane" || true
done
grep -Fq 'scripts/tests/fuzz/run-ci-fuzz.sh' "$CI_WORKFLOW" \
  || fail "ci.yml must call the shared fuzz runner"
# The runner must stay nightly-free: no cargo-fuzz, no nightly toolchain probe, no ASan guard.
grep -Fq 'cargo +nightly' "$FUZZ_DIR/run-ci-fuzz.sh" \
  && fail "fuzz runner must not invoke cargo +nightly on the stable lane" || true
grep -Fq 'rustup run nightly' "$FUZZ_DIR/run-ci-fuzz.sh" \
  && fail "fuzz runner must not probe the nightly toolchain on the stable lane" || true
grep -Fq -- '-Zsanitizer=address' "$FUZZ_DIR/run-ci-fuzz.sh" \
  && fail "fuzz runner must not require AddressSanitizer on the stable lane" || true
grep -Fq 'command -v cargo-fuzz' "$FUZZ_DIR/run-ci-fuzz.sh" \
  && fail "fuzz runner must not require cargo-fuzz on the stable lane" || true
[[ -f "$SCHEDULED_WORKFLOW" ]] || fail "scheduled fuzz workflow is missing"
grep -Fq 'schedule:' "$SCHEDULED_WORKFLOW" || fail "scheduled fuzz workflow has no schedule trigger"
grep -Fq 'actions/upload-artifact@v7' "$CI_WORKFLOW" \
  || fail "ci.yml must upload fuzz artifacts"
grep -Fq 'actions/upload-artifact@v7' "$SCHEDULED_WORKFLOW" \
  || fail "scheduled fuzz workflow must upload fuzz artifacts"

CRYPTO_TARGET="$FUZZ_DIR/src/targets/crypto_operations.rs"
grep -Fq 'PUBLIC_FORCE_AEAD_VALUES' "$CRYPTO_TARGET" \
  || fail "crypto fuzz target lacks the public AEAD value inventory"
grep -Fq 'INTERNAL_AEGIS_BACKEND_VALUES' "$CRYPTO_TARGET" \
  || fail "crypto fuzz target lacks the internal backend inventory"
for value in auto aegis-128l aegis128l aegis morus morus-1280-128 morus1280-128 aegis-128x4 aegis-128x8; do
  grep -Fq "\"$value\"" "$CRYPTO_TARGET" || fail "crypto fuzz target does not cover $value"
done

echo "[PASS] fuzz manifest, target inventory, curated seeds, CI lanes, and crypto contract are aligned on the stable lane"
