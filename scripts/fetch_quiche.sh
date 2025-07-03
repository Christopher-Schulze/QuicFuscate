#!/usr/bin/env bash
set -e

MIRROR_URL=${1:-https://github.com/cloudflare/quiche.git}
SUBMODULE_PATH="libs/quiche-patched"

if [ -n "$QUICHE_PATH" ] && [ -d "$QUICHE_PATH" ]; then
    echo "Using local quiche from $QUICHE_PATH"
    cd "$QUICHE_PATH"
    cargo build --release
    cargo clippy --all-targets -- -D warnings
    exit 0
fi

if [ ! -d "$SUBMODULE_PATH" ]; then
    mkdir -p "$SUBMODULE_PATH"
fi

echo "Fetching quiche from $MIRROR_URL ..."

if [ -f .gitmodules ] && grep -q "$SUBMODULE_PATH" .gitmodules; then
    git submodule set-url "$SUBMODULE_PATH" "$MIRROR_URL"
    git submodule update --init --recursive "$SUBMODULE_PATH"
else
    if [ ! -d "$SUBMODULE_PATH/.git" ]; then
        git clone "$MIRROR_URL" "$SUBMODULE_PATH"
    else
        git -C "$SUBMODULE_PATH" pull
    fi
fi

cd "$SUBMODULE_PATH"
cargo build --release
cargo clippy --all-targets -- -D warnings
