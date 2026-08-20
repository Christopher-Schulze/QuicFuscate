#!/usr/bin/env bash
# Description: Contract test: Performance --only scopes, skip evidence, and fail-closed summary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../lib/lib-common.sh"

RUNNER="$PROJECT_ROOT/scripts/tests/suites/test-performance-regression.sh"
CANONICAL_SCOPES="throughput,latency,memory,cpu,hotpath,simd,scalability,report"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-performance-scope.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  echo "[FAIL] $1" >&2
  exit 1
}

expect_status() {
  local expect="$1" log="$2"
  shift 2
  local status=0
  "$@" >"$log" 2>&1 || status=$?
  if [[ "$status" -ne "$expect" ]]; then
    echo "--- $log ---" >&2; cat "$log" >&2
    fail_fixture "expected exit $expect got $status for: $*"
  fi
}

install_cargo_shim() {
  local bin_dir="$1" cargo_log="$2"
  local real_cargo
  real_cargo="$(command -v cargo 2>/dev/null || which cargo 2>/dev/null || echo "/usr/local/cargo/bin/cargo")"
  mkdir -p "$bin_dir"
  cat >"$bin_dir/cargo" <<SH
#!/usr/bin/env bash
set -euo pipefail
LOG="\${QUICFUSCATE_CONTRACT_CARGO_LOG:-/dev/null}"
FAIL="\${QUICFUSCATE_CONTRACT_CARGO_FAIL:-0}"
REAL_CARGO="$real_cargo"
printf '%s\n' "\$*" >> "\$LOG"
if [[ "\$*" == *"metadata"* ]]; then
  if [[ -x "\$REAL_CARGO" ]]; then
    exec "\$REAL_CARGO" "\$@"
  else
    echo '{"packages":[],"workspace_members":[],"target_directory":"/tmp","version":1}' 
    exit 0
  fi
fi
if [[ "\$FAIL" == "1" ]]; then exit 1; fi
if [[ "\$*" == *"--list"* ]]; then
  echo "memory_usage: test"
  echo "pool_efficiency: test"
  echo "cpu_usage: test"
  echo "scalability_10: test"
  echo "scalability_100: test"
  echo "stream_scalability: test"
  exit 0
fi
if [[ "\$*" == *"bench"* ]]; then
  echo "Benchmarking \${@: -1}"
  echo "Benchmarking \$*"
  echo "Benchmarking sort_simd/1024_elems"
  echo "time: [1.0 us 2.0 us 3.0 us]"
elif [[ "\$*" == *"test"* ]]; then
  echo "running 1 test"
  echo "test \${@: -1} ... ok"
  echo "test result: ok. 1 passed; 0 failed"
else
  echo "running 1 test"
  echo "test result: ok. 1 passed"
fi
exit 0
SH
  chmod +x "$bin_dir/cargo"
}

run_runner() {
  local out_dir="$1" log="$2" cargo_log="$3"
  shift 3
  local bin_dir="$TMP_ROOT/bin"
  install_cargo_shim "$bin_dir" "$cargo_log"
  : >"$cargo_log"
  mkdir -p "$out_dir"
  local status=0
  env -u QUICFUSCATE_JSON_CONTRACT_TEST PATH="$bin_dir:$PATH" QUICFUSCATE_CONTRACT_CARGO_LOG="$cargo_log" bash "$RUNNER" --output-dir "$out_dir" "$@" >"$log" 2>&1 || status=$?
  echo "$status"
}

HELP_LOG="$TMP_ROOT/help.log"
expect_status 0 "$HELP_LOG" bash "$RUNNER" --help
grep -Fq "$CANONICAL_SCOPES" "$HELP_LOG" || fail_fixture "help is missing the canonical scope list"

INVALID_DIR="$TMP_ROOT/invalid-unknown"
expect_status 2 "$TMP_ROOT/unknown.log" bash "$RUNNER" --only nope --output-dir "$INVALID_DIR"
[[ ! -e "$INVALID_DIR" ]] || fail_fixture "unknown scope created an artifact directory"

EMPTY_DIR="$TMP_ROOT/invalid-empty"
expect_status 2 "$TMP_ROOT/empty.log" bash "$RUNNER" --only "" --output-dir "$EMPTY_DIR"
[[ ! -e "$EMPTY_DIR" ]] || fail_fixture "empty scope created an artifact directory"

MALFORMED_DIR="$TMP_ROOT/invalid-malformed"
expect_status 2 "$TMP_ROOT/malformed.log" bash "$RUNNER" --only "throughput,,cpu" --output-dir "$MALFORMED_DIR"
[[ ! -e "$MALFORMED_DIR" ]] || fail_fixture "malformed scope created an artifact directory"

COMBINED_ALL_DIR="$TMP_ROOT/invalid-all-combo"
expect_status 2 "$TMP_ROOT/all-combo.log" bash "$RUNNER" --only "all,throughput" --output-dir "$COMBINED_ALL_DIR"
[[ ! -e "$COMBINED_ALL_DIR" ]] || fail_fixture "all+scope combination created an artifact directory"

for scope in throughput latency memory cpu hotpath simd scalability report; do
  DIR="$TMP_ROOT/only-$scope"
  LOG="$TMP_ROOT/only-$scope.log"
  CARGO="$TMP_ROOT/only-$scope.cargo"
  status="$(run_runner "$DIR" "$LOG" "$CARGO" --only "$scope")"
  [[ "$status" == "0" ]] || fail_fixture "$scope scope exited $status"
  grep -Fq "[OK]" "$LOG" || { cat "$LOG"; fail_fixture "$scope scope missing [OK]"; }
  [[ -f "$DIR/performance_results.json" ]] || fail_fixture "$scope missing results.json"
done

FAST_DIR="$TMP_ROOT/fast-default"
FAST_LOG="$TMP_ROOT/fast-default.log"
FAST_CARGO="$TMP_ROOT/fast-default.cargo"
status="$(run_runner "$FAST_DIR" "$FAST_LOG" "$FAST_CARGO" --fast)"
[[ "$status" == "0" ]] || fail_fixture "unscoped fast exited $status"
python3 - "$FAST_DIR/performance_results.json" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
data=json.loads(p.read_text())
items=data.get("items", data) if isinstance(data, dict) else data
def find(n):
    return [x for x in items if x.get("name")==f"scope:{n}"]
for s in ["memory","cpu","simd"]:
    r=find(s)
    if not r or r[0].get("reason")!="fast_profile_omits_scope":
        print(f"fail {s} {r}", file=sys.stderr); sys.exit(1)
print("[OK] fast omits")
PY

echo "[PASS] performance --only scope contract"
