#!/usr/bin/env bash
# Description: Crypto micro-benchmark (fnv1a) quick mode

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

cargo run --features benches --quiet -- crypto-bench --iterations 80000 --payload 1024 --mode fnv1a
