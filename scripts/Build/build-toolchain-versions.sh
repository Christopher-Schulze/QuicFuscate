#!/usr/bin/env bash
# Description: Show toolchain versions

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
rustc -V
cargo -V
rustup show active-toolchain || true
