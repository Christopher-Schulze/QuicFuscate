#!/usr/bin/env bash
# Description: Export crypto-bench JSON artifact to artifacts/ with timestamp

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

mkdir -p artifacts
TS=$(date +%Y%m%d_%H%M%S)
OUT=artifacts/crypto-bench_${TS}.json
cargo run --features benches --quiet -- crypto-bench --iterations 200000 --payload 1200 --mode rolling --json | tee "$OUT"
echo "[artifact] $OUT"
