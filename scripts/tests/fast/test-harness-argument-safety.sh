#!/usr/bin/env bash
# Description: Contract test: harness arguments stay array-safe and fail closed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../lib/lib-common.sh"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-harness-argument-safety.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  error "harness argument safety fixture failed: $*"
  exit 1
}

expect_failure() {
  local log_file="$1"
  shift
  local status=0
  if "$@" > "$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -ne 0 ]] || fail_fixture "expected nonzero status: $*"
}

expect_json_item() {
  local json_file="$1"
  local expected_result="$2"
  local expected_reason="$3"
  python3 - "$json_file" "$expected_result" "$expected_reason" <<'PY'
import json
import sys

path, expected_result, expected_reason = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
items = document.get("items") or []
if not any(
    item.get("result") == expected_result and item.get("reason") == expected_reason
    for item in items
):
    raise SystemExit(
        f"missing result={expected_result!r}, reason={expected_reason!r} in {path}"
    )
PY
}

assert_no_marker() {
  local marker="$1"
  [[ ! -e "$marker" ]] || fail_fixture "unexpected side effect marker: $marker"
}

ORCHESTRATOR_DIR="$TMP_ROOT/orchestrator path;literal"
ORCHESTRATOR_MARKER="$TMP_ROOT/orchestrator-side-effect"
bash "$PROJECT_ROOT/scripts/benchmarks/suites/bench-orchestrator.sh" \
  --fast --dry-run --suite transport --output-dir "$ORCHESTRATOR_DIR" \
  > "$TMP_ROOT/orchestrator.log" 2>&1
expect_json_item "$ORCHESTRATOR_DIR/manifest.json" "SKIP" "dry_run"
python3 - "$ORCHESTRATOR_DIR/manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    document = json.load(handle)
item = document["items"][0]
if not isinstance(item.get("argv"), list) or item["argv"][-2] != "--output-dir":
    raise SystemExit("orchestrator manifest lost structured argv")
PY
assert_no_marker "$ORCHESTRATOR_MARKER"

E2E_DIR="$TMP_ROOT/e2e path;literal"
E2E_MARKER="$TMP_ROOT/e2e-side-effect"
bash "$PROJECT_ROOT/scripts/tests/suites/test-e2e-admin-web.sh" \
  --dry-run --output-dir "$E2E_DIR" \
  --admin-user 'user"\\value' \
  --admin-pass "pass;\$(touch $E2E_MARKER)" \
  --admin-addr 127.0.0.1:19000 --server-addr 127.0.0.1:19443 \
  --admin-web-root "$TMP_ROOT/web root;literal" \
  --use-binary "$TMP_ROOT/binary path;literal" \
  > "$TMP_ROOT/e2e.log" 2>&1
expect_json_item "$E2E_DIR/results.json" "SKIP" "dry_run"
if rg -Fq 'redacted' "$TMP_ROOT/e2e.log"; then
  :
else
  fail_fixture "dry-run output did not redact the admin password"
fi
assert_no_marker "$E2E_MARKER"

QPACK_DIR="$TMP_ROOT/qpack path;literal"
QPACK_MARKER="$TMP_ROOT/qpack-side-effect"
expect_failure "$TMP_ROOT/qpack.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/suites/bench-qpack-encode.sh" \
    --output-dir "$QPACK_DIR" \
    --sizes "64k bad;touch $QPACK_MARKER"
expect_json_item "$QPACK_DIR/results.json" "FAIL" "invalid_size"
assert_no_marker "$QPACK_MARKER"

UDP_DIR="$TMP_ROOT/udp path;literal"
UDP_MARKER="$TMP_ROOT/udp-side-effect"
expect_failure "$TMP_ROOT/udp.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/micro/micro-udpfast-throughput.sh" \
    --output-dir "$UDP_DIR" \
    --iters "1;touch $UDP_MARKER"
expect_json_item "$UDP_DIR/micro-udpfast-throughput.json" "FAIL" "invalid_cli_input"
assert_no_marker "$UDP_MARKER"

CRYPTO_DIR="$TMP_ROOT/crypto path;literal"
CRYPTO_MARKER="$TMP_ROOT/crypto-side-effect"
expect_failure "$TMP_ROOT/crypto.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/micro/micro-crypto-all.sh" \
    --output-dir "$CRYPTO_DIR" \
    --iters "0;touch $CRYPTO_MARKER"
expect_json_item "$CRYPTO_DIR/results.json" "FAIL" "invalid_cli_input_or_size"
assert_no_marker "$CRYPTO_MARKER"

RUN_CARGO_CAPTURE=(uninitialized)
run() {
  RUN_CARGO_CAPTURE=("$@")
}

unset RUSTFLAGS_EXTRA CARGO_TARGET_DIR CARGO_FEATURES JOBS
run_cargo metadata --no-deps
[[ "${#RUN_CARGO_CAPTURE[@]}" -eq 3 ]] \
  || fail_fixture "empty run_cargo environment changed argv length"
[[ "${RUN_CARGO_CAPTURE[0]}" == cargo \
  && "${RUN_CARGO_CAPTURE[1]}" == metadata \
  && "${RUN_CARGO_CAPTURE[2]}" == --no-deps ]] \
  || fail_fixture "empty run_cargo environment did not invoke cargo directly"

RUSTFLAGS_EXTRA="-C target-cpu=native"
run_cargo check --locked
[[ "${#RUN_CARGO_CAPTURE[@]}" -eq 5 ]] \
  || fail_fixture "populated run_cargo environment changed argv length"
[[ "${RUN_CARGO_CAPTURE[0]}" == env \
  && "${RUN_CARGO_CAPTURE[1]}" == "RUSTFLAGS=-C target-cpu=native" \
  && "${RUN_CARGO_CAPTURE[2]}" == cargo \
  && "${RUN_CARGO_CAPTURE[3]}" == check \
  && "${RUN_CARGO_CAPTURE[4]}" == --locked ]] \
  || fail_fixture "populated run_cargo environment lost assignment or cargo argv identity"
unset RUSTFLAGS_EXTRA

echo "[PASS] harness argument safety contract"
