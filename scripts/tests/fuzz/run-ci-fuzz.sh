#!/usr/bin/env bash
# Run every repository-owned libFuzzer target with the CI sanitizer contract.
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

command -v cargo-fuzz >/dev/null 2>&1 || die "cargo-fuzz is unavailable"
command -v rustup >/dev/null 2>&1 || die "rustup is unavailable; nightly is required"
rustup run nightly rustc -vV 2>/dev/null | grep -q nightly || die "nightly rustc is unavailable"

case " ${RUSTFLAGS:-} " in
  *" -Zsanitizer=address "*) ;;
  *) die "RUSTFLAGS must explicitly contain -Zsanitizer=address" ;;
esac

cargo +nightly metadata --manifest-path "$FUZZ_DIR/Cargo.toml" --no-deps --format-version 1 --locked >/dev/null \
  || die "fuzz manifest metadata resolution failed"

expected_targets="$(printf '%s\n' "${TARGETS[@]}" | sort)"
actual_targets="$(cargo +nightly fuzz list --fuzz-dir "$FUZZ_DIR" | sort)"
if [[ "$actual_targets" != "$expected_targets" ]]; then
  echo "Expected fuzz targets:" >&2
  printf '%s\n' "$expected_targets" >&2
  echo "Discovered fuzz targets:" >&2
  printf '%s\n' "$actual_targets" >&2
  die "fuzz target inventory mismatch"
fi

for target in "${TARGETS[@]}"; do
  corpus_dir="$FUZZ_DIR/corpus/$target"
  artifact_dir="$FUZZ_DIR/artifacts/$target"
  mkdir -p "$corpus_dir" "$artifact_dir"
  if [[ -d "$FUZZ_DIR/seeds/$target" ]]; then
    cp -a "$FUZZ_DIR/seeds/$target/." "$corpus_dir/"
  fi

  echo "[FUZZ] target=$target duration=${FUZZ_DURATION}s jobs=$FUZZ_JOBS"
  cargo +nightly fuzz run --fuzz-dir "$FUZZ_DIR" "$target" "$corpus_dir" -- \
    -jobs="$FUZZ_JOBS" \
    -max_total_time="$FUZZ_DURATION" \
    -runs=1000 \
    -max_len="$FUZZ_MAX_LEN" \
    -timeout="$FUZZ_TIMEOUT" \
    -artifact_prefix="$artifact_dir/"
done

echo "[PASS] all fuzz targets completed under the AddressSanitizer contract"
