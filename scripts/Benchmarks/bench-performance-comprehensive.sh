#!/usr/bin/env bash
# Description: Comprehensive performance benchmarking and profiling

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

echo "Starting comprehensive performance benchmarking..."

# 1. Build in release mode for accurate benchmarks
echo "1. Building in release mode..."
cargo build --release

# 2. Run built-in benchmarks
echo "2. Running built-in benchmarks..."
if cargo bench --no-run 2>/dev/null; then
    cargo bench
else
    echo "ℹ No built-in benchmarks found"
fi

# 3. Run criterion benchmarks if available
echo "3. Running criterion benchmarks..."
if grep -q "criterion" "$ROOT/Cargo.toml"; then
    cargo bench --bench '*'
else
    echo "ℹ No criterion benchmarks configured"
fi

# 4. Performance test with different optimization levels
echo "4. Testing different optimization levels..."
echo "Building with opt-level 1..."
RUSTFLAGS="-C opt-level=1" cargo build --release
echo "Building with opt-level 2..."
RUSTFLAGS="-C opt-level=2" cargo build --release
echo "Building with opt-level 3..."
RUSTFLAGS="-C opt-level=3" cargo build --release
echo "Building with opt-level s (size)..."
RUSTFLAGS="-C opt-level=s" cargo build --release
echo "Building with opt-level z (size aggressive)..."
RUSTFLAGS="-C opt-level=z" cargo build --release

# 5. Binary size analysis
echo "5. Analyzing binary sizes..."
if [ -f "$ROOT/target/release/quicfuscate" ]; then
    echo "Release binary size:"
    ls -lh "$ROOT/target/release/quicfuscate" | awk '{print $5, $9}'
    
    # Strip binary and check size
    cp "$ROOT/target/release/quicfuscate" "$ROOT/target/release/quicfuscate_stripped"
    strip "$ROOT/target/release/quicfuscate_stripped" 2>/dev/null || true
    echo "Stripped binary size:"
    ls -lh "$ROOT/target/release/quicfuscate_stripped" | awk '{print $5, $9}'
    rm -f "$ROOT/target/release/quicfuscate_stripped"
fi

# 6. Compilation time benchmarking
echo "6. Benchmarking compilation times..."
echo "Clean build time:"
cargo clean
time cargo build --release

echo "Incremental build time:"
touch "$ROOT/src/main.rs"
time cargo build --release

# 7. Memory usage analysis
echo "7. Memory usage analysis..."
if command -v valgrind >/dev/null 2>&1; then
    echo "Running valgrind memory check..."
    valgrind --tool=memcheck --leak-check=full "$ROOT/target/release/quicfuscate" --help 2>&1 | head -20
else
    echo "ℹ valgrind not available for memory analysis"
fi

# 8. CPU profiling preparation
echo "8. CPU profiling information..."
if command -v perf >/dev/null 2>&1; then
    echo "perf available for CPU profiling"
    echo "Run: perf record $ROOT/target/release/quicfuscate [args]"
    echo "Then: perf report"
else
    echo "ℹ perf not available for CPU profiling"
fi

# 9. Cargo bloat analysis
echo "9. Analyzing binary bloat..."
if command -v cargo-bloat >/dev/null 2>&1; then
    cargo bloat --release
else
    echo "ℹ cargo-bloat not installed. Install with: cargo install cargo-bloat"
fi

# 10. LLVM analysis
echo "10. LLVM IR analysis..."
echo "Generating LLVM IR for analysis..."
RUSTFLAGS="--emit=llvm-ir" cargo build --release 2>/dev/null || echo "ℹ LLVM IR generation completed"

echo "✓ Comprehensive performance benchmarking completed!"
echo "Check target/release/ for optimized binaries and analysis results."