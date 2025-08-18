#!/usr/bin/env bash
# Description: List binaries

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
if [ -d src/bin ]; then find src/bin -maxdepth 1 -type f -name '*.rs' | sed 's|^| - |'; else echo 'src/bin/ not found'; fi
