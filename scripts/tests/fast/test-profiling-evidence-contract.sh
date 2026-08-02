#!/usr/bin/env bash
# Description: Contract test: profiling runners fail closed and preserve evidence status.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib/lib-common.sh"
# shellcheck disable=SC1091
source "$PROJECT_ROOT/scripts/benchmarks/profiling-common.sh"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-profiling-evidence.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  error "profiling evidence contract fixture failed: $*"
  exit 1
}

expect_status() {
  local expected_status="$1"
  local log_file="$2"
  shift 2
  local status=0
  if "$@" >"$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -eq "$expected_status" ]] || fail_fixture "expected status $expected_status, got $status: $*"
}

assert_manifest() {
  local manifest="$1"
  local expected_result="$2"
  local expected_reason_fragment="$3"
  python3 - "$manifest" "$expected_result" "$expected_reason_fragment" <<'PY'
import json
import sys

manifest_path, expected_result, expected_reason_fragment = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    document = json.load(handle)
scenarios = document.get("scenarios") or []
if len(scenarios) != 1:
    raise SystemExit(f"expected one scenario in {manifest_path}, got {len(scenarios)}")
scenario = scenarios[0]
if scenario.get("result") != expected_result:
    raise SystemExit(f"expected result {expected_result}, got {scenario.get('result')}")
if expected_reason_fragment not in scenario.get("reason", ""):
    raise SystemExit(
        f"expected reason containing {expected_reason_fragment!r}, got {scenario.get('reason')!r}"
    )
raw = open(manifest_path, encoding="utf-8").read()
if "N/A" in raw:
    raise SystemExit(f"forbidden N/A marker in {manifest_path}")
PY
}

assert_no_side_effect() {
  local path="$1"
  [[ ! -e "$path" ]] || fail_fixture "unexpected side effect: $path"
}

BASELINE_OUTPUT="$TMP_ROOT/baseline path;literal"
expect_status 0 "$TMP_ROOT/baseline-dry-run.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-baseline.sh" \
  --dry-run --duration 1 --scenario a --output-dir "$BASELINE_OUTPUT"
BASELINE_MANIFEST="$(find "$BASELINE_OUTPUT" -name manifest.json -type f -print -quit)"
[[ -n "$BASELINE_MANIFEST" ]] || fail_fixture "baseline dry-run manifest missing"
assert_manifest "$BASELINE_MANIFEST" SKIP dry_run
assert_no_side_effect "$TMP_ROOT/baseline-side-effect"

TUN_OUTPUT="$TMP_ROOT/tun path;literal"
expect_status 0 "$TMP_ROOT/tun-dry-run.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-tun-mode.sh" \
  --dry-run --duration 1 --scenario g --output-dir "$TUN_OUTPUT"
TUN_MANIFEST="$(find "$TUN_OUTPUT" -name manifest.json -type f -print -quit)"
[[ -n "$TUN_MANIFEST" ]] || fail_fixture "TUN dry-run manifest missing"
assert_manifest "$TUN_MANIFEST" SKIP dry_run

ZC_OUTPUT="$TMP_ROOT/zc path;literal"
expect_status 0 "$TMP_ROOT/zc-dry-run.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-zc.sh" \
  --dry-run --duration 1 --output-dir "$ZC_OUTPUT"
ZC_MANIFEST="$(find "$ZC_OUTPUT" -name manifest.json -type f -print -quit)"
[[ -n "$ZC_MANIFEST" ]] || fail_fixture "zero-copy dry-run manifest missing"
assert_manifest "$ZC_MANIFEST" SKIP dry_run

MISSING_TOOLS_DIR="$TMP_ROOT/missing-flamegraph"
expect_status 2 "$TMP_ROOT/baseline-unavailable.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-baseline.sh" \
  --duration 1 --scenario a --flamegraph-dir "$MISSING_TOOLS_DIR" --output-dir "$TMP_ROOT/baseline-unavailable"
BASELINE_UNAVAILABLE="$(find "$TMP_ROOT/baseline-unavailable" -name manifest.json -type f -print -quit)"
assert_manifest "$BASELINE_UNAVAILABLE" UNAVAILABLE missing_flamegraph

expect_status 2 "$TMP_ROOT/tun-unavailable.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-tun-mode.sh" \
  --duration 1 --scenario g --flamegraph-dir "$MISSING_TOOLS_DIR" --output-dir "$TMP_ROOT/tun-unavailable"
TUN_UNAVAILABLE="$(find "$TMP_ROOT/tun-unavailable" -name manifest.json -type f -print -quit)"
assert_manifest "$TUN_UNAVAILABLE" UNAVAILABLE missing_flamegraph

expect_status 2 "$TMP_ROOT/zc-unavailable.log" \
  bash "$PROJECT_ROOT/scripts/benchmarks/profiling-zc.sh" \
  --duration 1 --flamegraph-dir "$MISSING_TOOLS_DIR" --output-dir "$TMP_ROOT/zc-unavailable"
ZC_UNAVAILABLE="$(find "$TMP_ROOT/zc-unavailable" -name manifest.json -type f -print -quit)"
assert_manifest "$ZC_UNAVAILABLE" UNAVAILABLE missing_flamegraph

printf '%s\n' '{"end": {}}' > "$TMP_ROOT/empty-iperf.json"
if profile_iperf_metrics_json "$TMP_ROOT/empty-iperf.json" >"$TMP_ROOT/iperf-metrics.log" 2>&1; then
  fail_fixture "empty iperf JSON was accepted as complete metrics"
fi
: > "$TMP_ROOT/empty-telemetry.txt"
if profile_telemetry_zc_json "$TMP_ROOT/empty-telemetry.txt" "$TMP_ROOT/empty-telemetry.txt" >"$TMP_ROOT/zc-metrics.log" 2>&1; then
  fail_fixture "empty telemetry was accepted as complete SendMsgZc metrics"
fi

for required_marker in \
  "server_not_ready" \
  "client_not_ready" \
  "required_metrics_missing" \
  "netem_setup_failed" \
  "flamegraph_generation_failed"; do
  if rg -Fq "$required_marker" \
    scripts/benchmarks/profiling-baseline.sh \
    scripts/benchmarks/profiling-tun-mode.sh \
    scripts/benchmarks/profiling-zc.sh; then
    continue
  fi
  fail_fixture "missing fail-closed marker: $required_marker"
done

if [[ "$(uname -s)" == Linux ]] && [[ "$(id -u)" -eq 0 ]] && \
  command -v perf >/dev/null 2>&1 && command -v tc >/dev/null 2>&1 && \
  command -v iperf3 >/dev/null 2>&1 && \
  [[ -x "$PROJECT_ROOT/target/release/quicfuscate" ]] && \
  [[ -x "$PROJECT_ROOT/target/release/harness" ]] && \
  [[ -f "$PROJECT_ROOT/config/local/server.crt" ]] && \
  [[ -f "$PROJECT_ROOT/config/local/server.key" ]] && \
  [[ -x /tmp/FlameGraph/flamegraph.pl ]] && \
  [[ -x /tmp/FlameGraph/stackcollapse-perf.pl ]]; then
  NATIVE_OUTPUT="$TMP_ROOT/native-process-failure"
  expect_status 1 "$TMP_ROOT/native-process-failure.log" \
    bash "$PROJECT_ROOT/scripts/benchmarks/profiling-baseline.sh" \
    --duration 1 --scenario d --binary /usr/bin/false --output-dir "$NATIVE_OUTPUT"
  NATIVE_MANIFEST="$(find "$NATIVE_OUTPUT" -name manifest.json -type f -print -quit)"
  assert_manifest "$NATIVE_MANIFEST" FAIL server_not_ready

  NETEM_OUTPUT="$TMP_ROOT/native-netem-failure"
  expect_status 1 "$TMP_ROOT/native-netem-failure.log" \
    bash "$PROJECT_ROOT/scripts/benchmarks/profiling-tun-mode.sh" \
    --duration 1 --scenario h --netem-interface qf-interface-does-not-exist --output-dir "$NETEM_OUTPUT"
  NETEM_MANIFEST="$(find "$NETEM_OUTPUT" -name manifest.json -type f -print -quit)"
  assert_manifest "$NETEM_MANIFEST" FAIL netem_setup_failed
fi

echo "[PASS] profiling evidence contract"
