#!/usr/bin/env bash
# Description: Check cargo fmt

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
cargo fmt --all -- --check
