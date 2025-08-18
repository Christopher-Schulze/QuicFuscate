#!/usr/bin/env bash
# Description: Run tests serially; if cargo-fuzz exists and fuzz/ is present, run a short fuzz job.

set -e

# Resolve repo root
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

cargo test --all-targets --release -- --test-threads=1 --nocapture
if command -v cargo-fuzz >/dev/null 2>&1 && [ -d fuzz ]; then
  (
    cd fuzz && cargo fuzz run fuzz_target_1 -- -max_total_time=60
  ) || true
else
  echo 'cargo-fuzz not installed or fuzz/ dir missing, skipping.'
fi
