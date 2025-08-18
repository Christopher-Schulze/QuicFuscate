#!/usr/bin/env bash
# Description: Export net-bench JSON artifact to artifacts/ with timestamp

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

mkdir -p artifacts
TS=$(date +%Y%m%d_%H%M%S)
OUT=artifacts/net-bench_${TS}.json
cargo run --features benches --release --quiet -- net-bench --iterations 100000 --payload 1200 --json | tee "$OUT"
echo "[artifact] $OUT"
