#!/usr/bin/env bash
# Description: Comprehensive Clippy audit with all lints and pedantic checks

set -e

# Resolve repo root
find_repo_root() {
  local d
  d="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
  while [ "$d" != "/" ]; do
    if [ -f "$d/Cargo.toml" ]; then echo "$d"; return; fi
    d="$(dirname "$d")"
  done
  echo "."
}
ROOT="$(find_repo_root)"; cd "$ROOT" || exit 1

echo "Running comprehensive Clippy audit..."

# Standard clippy check
echo "1. Standard Clippy check..."
cargo clippy --all-targets --all-features -- -D warnings

# Pedantic clippy check
echo "2. Pedantic Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::pedantic

# Nursery clippy check (experimental lints)
echo "3. Nursery Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::nursery

# Cargo clippy check (cargo-specific lints)
echo "4. Cargo-specific Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::cargo

# Performance-focused clippy check
echo "5. Performance Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::perf

# Complexity clippy check
echo "6. Complexity Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::complexity

# Style clippy check
echo "7. Style Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::style

# Correctness clippy check
echo "8. Correctness Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::correctness

# Suspicious clippy check
echo "9. Suspicious Clippy check..."
cargo clippy --all-targets --all-features -- -W clippy::suspicious

# Release mode clippy check
echo "10. Release mode Clippy check..."
cargo clippy --release --all-targets --all-features -- -D warnings

echo "✓ Comprehensive Clippy audit completed successfully!"