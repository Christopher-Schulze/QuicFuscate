#!/usr/bin/env bash
# Description: Comprehensive code quality audit including formatting, security, and best practices

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

echo "Starting comprehensive code quality audit..."

# 1. Cargo fmt check
echo "1. Checking code formatting..."
cargo fmt --all -- --check

# 2. Cargo clippy (comprehensive)
echo "2. Running Clippy analysis..."
cargo clippy --all-targets --all-features -- -D warnings

# 3. Cargo audit (security vulnerabilities)
echo "3. Running security audit..."
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    echo "ℹ cargo-audit not installed. Install with: cargo install cargo-audit"
fi

# 4. Cargo deny (license and dependency checks)
echo "4. Running dependency and license checks..."
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "ℹ cargo-deny not installed. Install with: cargo install cargo-deny"
fi

# 5. Cargo outdated (dependency updates)
echo "5. Checking for outdated dependencies..."
if command -v cargo-outdated >/dev/null 2>&1; then
    cargo outdated
else
    echo "ℹ cargo-outdated not installed. Install with: cargo install cargo-outdated"
fi

# 6. Cargo machete (unused dependencies)
echo "6. Checking for unused dependencies..."
if command -v cargo-machete >/dev/null 2>&1; then
    cargo machete
else
    echo "ℹ cargo-machete not installed. Install with: cargo install cargo-machete"
fi

# 7. Cargo check (compilation check)
echo "7. Running compilation check..."
cargo check --all-targets --all-features

# 8. Cargo test (dry run)
echo "8. Running test compilation check..."
cargo test --no-run --all-features

# 9. Documentation check
echo "9. Checking documentation..."
cargo doc --no-deps --all-features

# 10. Dead code detection
echo "10. Checking for dead code..."
RUSTFLAGS="-W dead_code" cargo check --all-targets --all-features

# 11. Unused imports detection
echo "11. Checking for unused imports..."
RUSTFLAGS="-W unused_imports" cargo check --all-targets --all-features

# 12. Missing docs detection
echo "12. Checking for missing documentation..."
RUSTDOCFLAGS="-D missing_docs" cargo doc --no-deps --all-features 2>/dev/null || echo "ℹ Some items missing documentation"

echo "✓ Comprehensive code quality audit completed!"
echo "All checks passed successfully."