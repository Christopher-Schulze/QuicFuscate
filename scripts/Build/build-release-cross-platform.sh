#!/usr/bin/env bash
# Description: Cross-platform release build script with automatic binary naming and copying

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

# Generate timestamp for release folder
TIMESTAMP=$(date +"%Y%m%d_%H%M")
RELEASE_DIR="$ROOT/releases/$TIMESTAMP"

echo "Creating release directory: $RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# Build targets
TARGETS=(
    "x86_64-apple-darwin:QuicFuscate_macos_amd64"
    "aarch64-apple-darwin:QuicFuscate_macos_arm64"
    "x86_64-pc-windows-gnu:QuicFuscate_windows_amd64.exe"
    "x86_64-unknown-linux-gnu:QuicFuscate_linux_amd64"
    "aarch64-unknown-linux-gnu:QuicFuscate_linux_arm64"
)

echo "Building release binaries..."

for target_info in "${TARGETS[@]}"; do
    IFS=':' read -r target binary_name <<< "$target_info"
    
    echo "Building for target: $target"
    
    # Add target if not already installed
    rustup target add "$target" 2>/dev/null || true
    
    # Build for target
    if cargo build --release --target="$target"; then
        # Determine source binary path
        if [[ "$target" == *"windows"* ]]; then
            source_binary="$ROOT/target/$target/release/quicfuscate.exe"
        else
            source_binary="$ROOT/target/$target/release/quicfuscate"
        fi
        
        # Copy and rename binary
        if [ -f "$source_binary" ]; then
            cp "$source_binary" "$RELEASE_DIR/$binary_name"
            echo "✓ Built and copied: $binary_name"
        else
            echo "⚠ Binary not found: $source_binary"
        fi
    else
        echo "✗ Failed to build for target: $target"
    fi
done

echo "Release build completed in: $RELEASE_DIR"
echo "Binaries created:"
ls -la "$RELEASE_DIR/"

# Clean up target directory
echo "Cleaning target directory..."
cargo clean

echo "Release process completed successfully!"