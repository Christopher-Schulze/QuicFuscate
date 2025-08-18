#!/usr/bin/env bash
# Description: Net benchmark quick mode

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

cargo run --features benches --quiet -- net-bench --iterations 60000 --payload 1200
