#!/usr/bin/env bash
# Description: Pool benchmark quick mode

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

cargo run --features benches --quiet -- pool-bench --iterations 50000 --payload 800 --pool-capacity 1024 --block-size 4096
