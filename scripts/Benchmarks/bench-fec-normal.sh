#!/usr/bin/env bash
# Description: FEC benchmark comparing parallel vs sequential modes

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

cargo run --features benches --release --quiet -- fec-bench --packets 8192 --payload 1200 --mode normal
