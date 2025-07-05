#!/bin/bash
set -e

QUIC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCHED_DIR="$QUIC_DIR/libs/patched_quiche"
BUILD_DIR="$QUIC_DIR/quiche_build"

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[QUICHE]${NC} $1"
}

# 1. Clean and prepare build directory
log "Preparing build directory..."
rm -rf "$BUILD_DIR"
cp -r "$PATCHED_DIR" "$BUILD_DIR"

# 2. Build optimized version
log "Building optimized version..."
cd "$BUILD_DIR/quiche"
# Clean any existing build artifacts
cargo clean

# Build with optimized flags
RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1" \
RUSTC_WRAPPER="" \
cargo build --release --features "ffi qlog boringssl-vendored" --no-default-features

# 3. Create symlink for easy access
ln -sf "$BUILD_DIR/quiche" "$QUIC_DIR/quiche"
log "Symlink created: $QUIC_DIR/quiche -> $BUILD_DIR/quiche"

log "✅ Done! Optimized quiche is ready in: $BUILD_DIR/quiche/target/release"
