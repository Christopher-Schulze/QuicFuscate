#!/usr/bin/env bash
set -euo pipefail

# Fetch or reuse a patched quiche source tree.
# Usage: ./scripts/fetch_quiche.sh [mirror-url]
# Optional environment variables:
#   QUICHE_PATH  Use an existing local quiche checkout instead of cloning.
#   QUICHE_COMMIT  Commit hash to checkout (defaults to pinned revision).
#

MIRROR_URL=${1:-""}
QUICHE_REPO=${MIRROR_URL:-"https://github.com/cloudflare/quiche.git"}
QUICHE_COMMIT=${QUICHE_COMMIT:-"5700a7c74927d2c4912ac95e904c6ad3642b6868"}
DEST_DIR="libs/patched_quiche/quiche"

if [ -n "${QUICHE_PATH:-}" ]; then
    echo "Using local quiche from $QUICHE_PATH"
    rm -rf "$DEST_DIR"
    mkdir -p "$(dirname "$DEST_DIR")"
    cp -R "$QUICHE_PATH" "$DEST_DIR"
else
    if [ -d "$DEST_DIR/.git" ]; then
        git -C "$DEST_DIR" fetch --depth 1 "$QUICHE_REPO" "$QUICHE_COMMIT"
    else
        rm -rf "$DEST_DIR"
        git clone --depth 1 "$QUICHE_REPO" "$DEST_DIR"
    fi
    git -C "$DEST_DIR" checkout "$QUICHE_COMMIT"
fi

pushd "$DEST_DIR" > /dev/null
cargo build --release
popd > /dev/null
