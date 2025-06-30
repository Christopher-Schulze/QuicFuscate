#!/usr/bin/env bash
set -e

MIRROR_URL=${1:-https://github.com/cloudflare/quiche.git}
SUBMODULE_PATH="libs/quiche-patched"

# Update submodule URL to provided mirror
if [ ! -d "$SUBMODULE_PATH" ]; then
    mkdir -p "$SUBMODULE_PATH"
fi
git submodule set-url "$SUBMODULE_PATH" "$MIRROR_URL"

echo "Fetching quiche from $MIRROR_URL ..."

git submodule update --init "$SUBMODULE_PATH"

# Build the patched quiche library
( cd "$SUBMODULE_PATH" && cargo build --release )
