#!/usr/bin/env bash
# Description: Clean target directory

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
cargo clean
