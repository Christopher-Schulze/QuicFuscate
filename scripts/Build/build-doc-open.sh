#!/usr/bin/env bash
# Description: Open documentation

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
cargo doc --no-deps --open
