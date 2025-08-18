#!/usr/bin/env bash
# Description: Quick fec-bench sanity run on small packet set.

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

cargo run --features benches --quiet -- fec-bench --packets 512 --payload 800 --mode normal
