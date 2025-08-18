#!/usr/bin/env bash
# Description: Export pool-bench JSON artifact to artifacts/ with timestamp

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

mkdir -p artifacts
TS=$(date +%Y%m%d_%H%M%S)
OUT=artifacts/pool-bench_${TS}.json
cargo run --features benches --quiet -- pool-bench --iterations 200000 --payload 1024 --pool-capacity 1024 --block-size 4096 --json | tee "$OUT"
echo "[artifact] $OUT"
