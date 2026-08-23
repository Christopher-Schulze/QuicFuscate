#!/usr/bin/env bash
# Run the stable deterministic fuzz verification suite across every retained target.
#
# This replaces the previous nightly-only `cargo-fuzz` + AddressSanitizer lane. The suite is a
# corpus + generated-input regression net executed via `cargo test` on the stable toolchain. It is
# not coverage-guided; it catches panics, aborts, and out-of-bounds regressions over the curated
# seeds plus a deterministic byte generator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz"

readonly TARGETS=(
  connection_handling
  crypto_operations
  fec_encoding
  frame_decoding
  packet_parsing
  varint_parsing
)

die() {
  echo "[FAIL] $*" >&2
  exit 1
}

positive_int() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

# Optional knobs kept for parity with callers; the stable lane ignores FUZZ_DURATION/FUZZ_JOBS
# because `cargo test` owns its own scheduling and lifetime.
FUZZ_RELEASE="${FUZZ_RELEASE:-1}"

for var in FUZZ_DURATION FUZZ_JOBS FUZZ_MAX_LEN FUZZ_TIMEOUT; do
  if [[ -n "${!var:-}" ]]; then
    : "${!var}"
  fi
done
FUZZ_DURATION="${FUZZ_DURATION:-60}"
FUZZ_JOBS="${FUZZ_JOBS:-2}"
FUZZ_MAX_LEN="${FUZZ_MAX_LEN:-65536}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-10}"
positive_int "$FUZZ_DURATION" || die "FUZZ_DURATION must be a positive integer"
positive_int "$FUZZ_JOBS" || die "FUZZ_JOBS must be a positive integer"
positive_int "$FUZZ_MAX_LEN" || die "FUZZ_MAX_LEN must be a positive integer"
positive_int "$FUZZ_TIMEOUT" || die "FUZZ_TIMEOUT must be a positive integer"
(( FUZZ_DURATION <= 3600 )) || die "FUZZ_DURATION exceeds the 3600 second safety bound"
(( FUZZ_JOBS <= 64 )) || die "FUZZ_JOBS exceeds the 64 worker safety bound"
(( FUZZ_MAX_LEN <= 1048576 )) || die "FUZZ_MAX_LEN exceeds the 1 MiB safety bound"
(( FUZZ_TIMEOUT <= 120 )) || die "FUZZ_TIMEOUT exceeds the 120 second safety bound"

[[ -f "$FUZZ_DIR/Cargo.toml" ]] || die "fuzz manifest is missing"

# The declared inventory must match the source-owned list exactly before any execution.
expected_targets="$(printf '%s\n' "${TARGETS[@]}" | sort)"
actual_targets="$(
  sed -n 's/^pub mod \([a-z_0-9]*\);$/\1/p' "$FUZZ_DIR/src/targets.rs" | sort
)"
if [[ "$actual_targets" != "$expected_targets" ]]; then
  echo "Expected fuzz targets:" >&2
  printf '%s\n' "$expected_targets" >&2
  echo "Discovered fuzz targets:" >&2
  printf '%s\n' "$actual_targets" >&2
  die "fuzz target inventory mismatch"
fi

# Manifest must stay resolvable on the stable toolchain without network access.
cargo metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --format-version 1 --locked >/dev/null \
  || die "fuzz manifest metadata resolution failed"

release_flag=()
if [[ "$FUZZ_RELEASE" == "1" ]]; then
  release_flag=(--release)
fi

# Each target runs as its own test so a regression names the offending surface. Test threads are
# left to Cargo's default scheduler; FUZZ_JOBS only gates CI worker sizing upstream of this call.
cargo test "${release_flag[@]}" \
  --manifest-path "$FUZZ_DIR/Cargo.toml" \
  -- \
  --test-threads="$FUZZ_JOBS"

echo "[PASS] all fuzz targets completed under the stable deterministic contract"
