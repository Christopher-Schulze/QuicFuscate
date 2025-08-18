#!/usr/bin/env bash
# Description: macOS-only release build script with timestamp-based release management
# This script builds only for macOS targets to avoid cross-compilation dependencies

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

# Generate timestamp for release folder (YYYYMMDD_HHMM)
TIMESTAMP=$(date +"%Y%m%d_%H%M")
RELEASE_DIR="$ROOT/releases/$TIMESTAMP"

echo "Creating macOS release directory: $RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# macOS build targets only
TARGETS=(
    "x86_64-apple-darwin:QuicFuscate_macos_amd64"
    "aarch64-apple-darwin:QuicFuscate_macos_arm64"
)

echo "Building macOS release binaries..."
echo "Timestamp: $TIMESTAMP"

for target_info in "${TARGETS[@]}"; do
    IFS=':' read -r target binary_name <<< "$target_info"
    
    echo "Building for macOS target: $target"
    
    # Add target if not already installed
    rustup target add "$target" 2>/dev/null || true
    
    # Build for target
    if cargo build --release --target="$target"; then
        source_binary="$ROOT/target/$target/release/quicfuscate"
        
        # Copy and rename binary
        if [ -f "$source_binary" ]; then
            cp "$source_binary" "$RELEASE_DIR/$binary_name"
            chmod +x "$RELEASE_DIR/$binary_name"
            echo "✓ Built and copied: $binary_name"
        else
            echo "⚠ Binary not found: $source_binary"
        fi
    else
        echo "✗ Failed to build for target: $target"
        exit 1
    fi
done

echo "macOS release build completed in: $RELEASE_DIR"
echo "Binaries created:"
ls -la "$RELEASE_DIR/"

# Create release info file
cat > "$RELEASE_DIR/release_info.txt" << EOF
QuicFuscate macOS Release
Build Date: $(date)
Timestamp: $TIMESTAMP
Targets Built:
- x86_64-apple-darwin (Intel)
- aarch64-apple-darwin (Apple Silicon)

Binaries:
- QuicFuscate_macos_amd64 (Intel Macs)
- QuicFuscate_macos_arm64 (Apple Silicon Macs)
EOF

# Clean up target directory
echo "Cleaning target directory..."
cargo clean

echo "macOS release process completed successfully!"
echo "Release available at: $RELEASE_DIR"