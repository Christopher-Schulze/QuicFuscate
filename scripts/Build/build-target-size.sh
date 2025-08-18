#!/usr/bin/env bash
# Description: Show target size

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1
if [ -d target ]; then du -sh target; else echo 'target/ not found'; fi
