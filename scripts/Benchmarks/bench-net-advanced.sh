#!/usr/bin/env bash
# Description: Net benchmark with advanced profiling (JSON/time)

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

TIME_CMD=""
if command -v gtime >/dev/null 2>&1; then TIME_CMD='gtime -v';
elif /usr/bin/time -v true >/dev/null 2>&1; then TIME_CMD='/usr/bin/time -v';
elif /usr/bin/time -lp true >/dev/null 2>&1; then TIME_CMD='/usr/bin/time -lp';
elif command -v time >/dev/null 2>&1 && time -v true >/dev/null 2>&1; then TIME_CMD='time -v';
fi
CMD="cargo run --features benches --release --quiet -- net-bench --iterations 100000 --payload 1200 --json"
if [ -n "$TIME_CMD" ]; then eval "$TIME_CMD $CMD"; else eval "$CMD"; fi
