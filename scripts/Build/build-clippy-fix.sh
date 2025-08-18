#!/usr/bin/env bash
# Description: Apply clippy fixes

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
cargo clippy --fix --allow-dirty --allow-staged || cargo clippy
