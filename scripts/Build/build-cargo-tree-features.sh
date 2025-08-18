#!/usr/bin/env bash
# Description: Show cargo tree with features

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
cargo tree -e features
