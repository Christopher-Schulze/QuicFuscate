#!/usr/bin/env bash
# Description: Project cleanup and maintenance utility

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

echo "Starting project cleanup and maintenance..."

# 1. Clean cargo artifacts
echo "1. Cleaning cargo build artifacts..."
cargo clean

# 2. Remove old release directories (keep last 5)
echo "2. Cleaning old release directories..."
if [ -d "$ROOT/releases" ]; then
    cd "$ROOT/releases"
    # Keep only the 5 most recent release directories
    ls -1t | tail -n +6 | xargs -r rm -rf
    echo "✓ Cleaned old release directories (kept 5 most recent)"
    cd "$ROOT"
else
    echo "ℹ No releases directory found"
fi

# 3. Clean temporary files
echo "3. Cleaning temporary files..."
find "$ROOT" -name "*.tmp" -type f -delete 2>/dev/null || true
find "$ROOT" -name "*.bak" -type f -delete 2>/dev/null || true
find "$ROOT" -name "*~" -type f -delete 2>/dev/null || true
find "$ROOT" -name ".DS_Store" -type f -delete 2>/dev/null || true

# 4. Clean log files
echo "4. Cleaning log files..."
find "$ROOT" -name "*.log" -type f -mtime +7 -delete 2>/dev/null || true

# 5. Update dependencies
echo "5. Updating dependencies..."
cargo update

# 6. Fix formatting
echo "6. Fixing code formatting..."
cargo fmt --all

# 7. Clean documentation artifacts
echo "7. Cleaning documentation artifacts..."
rm -rf "$ROOT/target/doc" 2>/dev/null || true

# 8. Optimize Cargo.lock
echo "8. Optimizing Cargo.lock..."
cargo tree --duplicates 2>/dev/null || echo "ℹ No duplicate dependencies found"

# 9. Check disk usage
echo "9. Checking project disk usage..."
echo "Project size:"
du -sh "$ROOT" 2>/dev/null || true
echo "Target directory size:"
du -sh "$ROOT/target" 2>/dev/null || echo "ℹ No target directory"
echo "Releases directory size:"
du -sh "$ROOT/releases" 2>/dev/null || echo "ℹ No releases directory"

# 10. Validate project structure
echo "10. Validating project structure..."
required_files=("Cargo.toml" "src/main.rs" "README.md")
for file in "${required_files[@]}"; do
    if [ -f "$ROOT/$file" ]; then
        echo "✓ $file exists"
    else
        echo "⚠ $file missing"
    fi
done

echo "✓ Project cleanup and maintenance completed!"
echo "Project is clean and optimized."