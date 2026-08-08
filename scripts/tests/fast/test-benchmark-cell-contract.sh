#!/usr/bin/env bash
# Description: Contract test: benchmark cells fail closed and retain identity.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-benchmark-cell-contract.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

FAKE_BIN="$TMP_ROOT/fake-bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "metadata" ]]; then
  printf '%s\n' '{"packages":[{"targets":[{"name":"ci_regression","kind":["bench"]}]}]}'
  exit 0
fi
if [[ "${1:-}" == "bench" ]]; then
  if [[ "${FAKE_CARGO_EXPORT_FAILURE:-0}" == "1" && "${*}" == *"--message-format=json"* ]]; then
    echo "synthetic benchmark export failure" >&2
    exit 42
  fi
  if [[ "${FAKE_CARGO_EMPTY_FILTER:-0}" == "1" && "${*}" != *"--no-run"* ]]; then
    echo "Finished empty benchmark selection"
    exit 0
  fi
  if [[ "${*}" == *"--no-run"* ]]; then
    echo "Finished benchmark preflight"
    exit 0
  fi
  filter="${@: -1}"
  echo "Benchmarking ${filter}"
  echo "time: [1 ns 2 ns 3 ns]"
  exit 0
fi
if [[ "${1:-}" == "build" ]]; then
  echo "Finished synthetic build"
  exit 0
fi
if [[ "${1:-}" == "test" ]]; then
  echo "running 0 tests"
  echo "test result: ok. 0 passed; 0 failed"
  exit 0
fi
echo "unsupported fake cargo command: $*" >&2
exit 127
EOF
chmod +x "$FAKE_BIN/cargo"

OUTPUT_DIR="$TMP_ROOT/performance"
set +e
PATH="$FAKE_BIN:$PATH" FAKE_CARGO_EMPTY_FILTER=1 \
  bash scripts/tests/suites/test-performance-regression.sh --fast --output-dir "$OUTPUT_DIR" \
  >"$TMP_ROOT/performance.log" 2>&1
RC=$?
set -e
[[ "$RC" -eq 1 ]] || { echo "empty benchmark filters unexpectedly returned $RC" >&2; exit 1; }

python3 - "$OUTPUT_DIR/performance_results.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
items = document["items"]
requested = {
    "aes_gcm_seal/1024B",
    "data_aead_single_seal_batch/aegis128l_1400B",
    "connection_1rtt_send_recv/payload_1024B",
    "stream_frame_encoding/1024B_direct_writer",
    "varint/roundtrip_8vals",
}
by_cell = {item["cell"]: item for item in items if "cell" in item}
missing = requested - by_cell.keys()
assert not missing, missing
for cell in requested:
    item = by_cell[cell]
    assert item["result"] == "FAIL", item
    assert item["status"] == "FAIL", item
    assert item["reason"] == "benchmark_filter_matched_nothing", item
    assert item["command_status"] == 0, item
    assert item["target"] == "bench:ci_regression", item
    assert "--bench" in item["argv"], item
assert all("simd_xor" not in str(item) for item in items), items
for item in items:
    for key in ("cell", "status", "result", "reason", "argv", "environment", "command_status"):
        assert key in item, (key, item)
PY

PLATFORM_DIR="$TMP_ROOT/linux-send-path"
bash scripts/benchmarks/suites/bench-linux-send-path-decision.sh --fast --dry-run \
  --output-dir "$PLATFORM_DIR" >"$TMP_ROOT/linux-send-path.log" 2>&1
python3 - "$PLATFORM_DIR/results.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
items = [item for item in document["items"] if item.get("cell")]
assert items, document
assert all(item["result"] == "SKIP" for item in items), items
assert all(item["reason"] == "platform_requires_linux" for item in items), items
assert all(item["command_status"] == 0 for item in items), items
PY

EXPORT_DIR="$TMP_ROOT/transport-export"
set +e
PATH="$FAKE_BIN:$PATH" FAKE_CARGO_EXPORT_FAILURE=1 \
  bash scripts/benchmarks/suites/bench-transport.sh --fast --output-dir "$EXPORT_DIR" \
  >"$TMP_ROOT/transport-export.log" 2>&1
RC=$?
set -e
[[ "$RC" -eq 42 ]] || { echo "export failure unexpectedly returned $RC" >&2; exit 1; }
python3 - "$EXPORT_DIR/results.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
exports = [item for item in document["items"] if item.get("cell") == "export"]
assert len(exports) == 1, exports
item = exports[0]
assert item["result"] == "FAIL", item
assert item["reason"] == "result_export_failed", item
assert item["command_status"] == 42, item
assert "--message-format=json" in item["argv"], item
PY

SUITE_DIR="$TMP_ROOT/transport-cell-failure"
set +e
PATH="$FAKE_BIN:$PATH" FAKE_CARGO_EMPTY_FILTER=1 \
  bash scripts/benchmarks/suites/bench-transport.sh --fast --output-dir "$SUITE_DIR" \
  >"$TMP_ROOT/transport-cell-failure.log" 2>&1
RC=$?
set -e
[[ "$RC" -eq 1 ]] || { echo "per-cell benchmark failure unexpectedly returned $RC" >&2; exit 1; }
python3 - "$SUITE_DIR/results.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
cells = [item for item in document["items"] if item.get("cell") == "varint"]
assert len(cells) == 1, cells
item = cells[0]
assert item["result"] == "FAIL", item
assert item["reason"] == "benchmark_filter_matched_nothing", item
assert item["command_status"] == 0, item
PY

echo "[PASS] benchmark cell contract: identities, exact filters, failures, and platform skips are explicit"
