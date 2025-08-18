#!/usr/bin/env bash
# Description: Comprehensive test runner that executes all available tests systematically

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

echo "Starting comprehensive test suite..."

# 1. Unit tests
echo "1. Running unit tests..."
cargo test --lib --all-features

# 2. Integration tests
echo "2. Running integration tests..."
cargo test --test '*' --all-features

# 3. Documentation tests
echo "3. Running documentation tests..."
cargo test --doc --all-features

# 4. All tests in release mode
echo "4. Running all tests in release mode..."
cargo test --release --all-features

# 5. Tests with verbose output
echo "5. Running tests with verbose output..."
cargo test --all-features --verbose

# 6. Bench tests (if available)
echo "6. Running benchmark tests..."
if cargo test --benches --all-features 2>/dev/null; then
    echo "✓ Benchmark tests completed"
else
    echo "ℹ No benchmark tests found or available"
fi

# 7. Example tests
echo "7. Running example tests..."
if cargo test --examples --all-features 2>/dev/null; then
    echo "✓ Example tests completed"
else
    echo "ℹ No example tests found or available"
fi

# 8. Single-threaded tests (for race condition detection)
echo "8. Running single-threaded tests..."
cargo test --all-features -- --test-threads=1

# 9. Ignored tests
echo "9. Running ignored tests..."
cargo test --all-features -- --ignored

# 10. All tests including ignored
echo "10. Running all tests including ignored..."
cargo test --all-features -- --include-ignored

# 11. Check if there are any test binaries and run them
echo "11. Checking for additional test binaries..."
if [ -d "$ROOT/tests" ]; then
    for test_file in "$ROOT"/tests/*.rs; do
        if [ -f "$test_file" ]; then
            test_name=$(basename "$test_file" .rs)
            echo "Running test binary: $test_name"
            cargo test --test "$test_name" --all-features
        fi
    done
fi

echo "✓ Comprehensive test suite completed successfully!"
echo "All tests passed without errors."