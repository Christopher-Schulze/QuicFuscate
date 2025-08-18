#!/bin/bash

# QuicFuscate macOS ARM64 Release Build Script
# Builds only for aarch64-apple-darwin target

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}QuicFuscate macOS ARM64 Release Build${NC}"
echo "======================================"

# Find repository root
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$REPO_ROOT"

echo -e "${YELLOW}Repository root: $REPO_ROOT${NC}"

# Create timestamp for release directory
TIMESTAMP=$(date +"%Y%m%d_%H%M")
RELEASE_DIR="$REPO_ROOT/releases/$TIMESTAMP"

echo -e "${YELLOW}Creating release directory: $RELEASE_DIR${NC}"
mkdir -p "$RELEASE_DIR"

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
cargo clean

# Add macOS ARM64 target if not already added
echo -e "${YELLOW}Ensuring aarch64-apple-darwin target is available...${NC}"
rustup target add aarch64-apple-darwin

# Build for macOS ARM64
echo -e "${BLUE}Building for aarch64-apple-darwin...${NC}"
if cargo build --release --target aarch64-apple-darwin; then
    echo -e "${GREEN}✓ Successfully built for aarch64-apple-darwin${NC}"
else
    echo -e "${RED}✗ Failed to build for aarch64-apple-darwin${NC}"
    exit 1
fi

# Find and copy binaries
echo -e "${YELLOW}Copying binaries to release directory...${NC}"
BINARY_COUNT=0

# Look for binaries in target directory
TARGET_DIR="$REPO_ROOT/target/aarch64-apple-darwin/release"
if [ -d "$TARGET_DIR" ]; then
    for binary in "$TARGET_DIR"/*; do
        if [ -f "$binary" ] && [ -x "$binary" ] && [[ ! "$binary" =~ \.(d|rlib|so|dylib)$ ]]; then
            BASENAME=$(basename "$binary")
            # Skip if it's a build artifact or has extension
            if [[ ! "$BASENAME" =~ \. ]] && [[ "$BASENAME" != "build" ]] && [[ "$BASENAME" != "deps" ]]; then
                NEW_NAME="${BASENAME}_macos_arm64"
                echo -e "  ${GREEN}Copying: $BASENAME -> $NEW_NAME${NC}"
                cp "$binary" "$RELEASE_DIR/$NEW_NAME"
                chmod +x "$RELEASE_DIR/$NEW_NAME"
                BINARY_COUNT=$((BINARY_COUNT + 1))
            fi
        fi
    done
fi

# Create release info file
RELEASE_INFO="$RELEASE_DIR/release_info.txt"
echo "QuicFuscate macOS ARM64 Release" > "$RELEASE_INFO"
echo "==============================" >> "$RELEASE_INFO"
echo "Build Date: $(date)" >> "$RELEASE_INFO"
echo "Target: aarch64-apple-darwin" >> "$RELEASE_INFO"
echo "Rust Version: $(rustc --version)" >> "$RELEASE_INFO"
echo "Cargo Version: $(cargo --version)" >> "$RELEASE_INFO"
echo "Repository: $(git remote get-url origin 2>/dev/null || echo 'Unknown')" >> "$RELEASE_INFO"
echo "Commit: $(git rev-parse HEAD 2>/dev/null || echo 'Unknown')" >> "$RELEASE_INFO"
echo "Branch: $(git branch --show-current 2>/dev/null || echo 'Unknown')" >> "$RELEASE_INFO"
echo "Binaries: $BINARY_COUNT" >> "$RELEASE_INFO"
echo "" >> "$RELEASE_INFO"
echo "Files in this release:" >> "$RELEASE_INFO"
ls -la "$RELEASE_DIR" >> "$RELEASE_INFO"

# Clean up after build
echo -e "${YELLOW}Cleaning up build artifacts...${NC}"
cargo clean

# Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}macOS ARM64 Release Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Release directory: $RELEASE_DIR${NC}"
echo -e "${YELLOW}Binaries copied: $BINARY_COUNT${NC}"
echo -e "${YELLOW}Target: aarch64-apple-darwin${NC}"
echo ""
echo -e "${BLUE}Contents of release directory:${NC}"
ls -la "$RELEASE_DIR"
echo ""
echo -e "${GREEN}Build completed successfully!${NC}"