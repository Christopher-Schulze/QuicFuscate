#!/usr/bin/env bash
# Description: Contract test: Optimization --only scopes, skip evidence, and fail-closed summary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../lib/lib-common.sh"

RUNNER="$PROJECT_ROOT/scripts/tests/suites/test-optimization.sh"
FULL_SUITE="$PROJECT_ROOT/scripts/tests/utils/util-run-full-suite.sh"
CANONICAL_SCOPES="batch,memory,simd,cpu,zero-copy,telemetry,integration,stress"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-optimization-scope.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  error "optimization scope contract failed: $*"
  exit 1
}

expect_status() {
  local expected="$1"
  local log_file="$2"
  shift 2
  local status=0
  if "$@" >"$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  [[ "$status" -eq "$expected" ]] || fail_fixture "expected status $expected, got $status: $* (log $log_file)"
}

install_cargo_shim() {
  local bin_dir="$1"
  local log_file="$2"
  mkdir -p "$bin_dir"
  cat >"$bin_dir/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
log_file="${QUICFUSCATE_CONTRACT_CARGO_LOG:?}"
{
  printf 'ARGV'
  printf ' %s' "$@"
  printf '\n'
  printf 'ENV NUMA=%s HUGEPAGE=%s TELEMETRY=%s RUSTFLAGS=%s CARGO_FEATURES=%s\n' \
    "${QUICFUSCATE_NUMA_POLICY-}" \
    "${QUICFUSCATE_MADVISE_HUGEPAGE-}" \
    "${QUICFUSCATE_TELEMETRY-}" \
    "${RUSTFLAGS-}" \
    "${CARGO_FEATURES-}"
} >>"$log_file"

is_list=0
for arg in "$@"; do
  if [[ "$arg" == "--list" ]]; then
    is_list=1
    break
  fi
done

if [[ "${QUICFUSCATE_CONTRACT_CARGO_FAIL:-0}" == "1" && "$is_list" -eq 0 ]]; then
  echo "running 1 test"
  echo "test injected_scope_failure ... FAILED"
  echo "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"
  exit 1
fi

if [[ "$is_list" -eq 1 ]]; then
  cat <<'LIST'
normalized_batch_size_helper: test
cpu_profile_mask_helper: test
test_batch_processing_helper: test
numa_policy_helper: test
hugepages_helper: test
sse2_path_helper: test
avx2_path_helper: test
avx512_path_helper: test
neon_path_helper: test
pmull_path_helper: test
cpu_features_helper: test
prefetch_helper: test
cache_alignment_helper: test
zero_copy_helper: test
batch_processing_helper: test
telemetry_helper: test
optimization_stress_helper: test
LIST
  exit 0
fi

echo "running 1 test"
echo "test stub_scope_body ... ok"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
exit 0
SH
  chmod +x "$bin_dir/cargo"
}

run_runner() {
  local output_dir="$1"
  local log_file="$2"
  local cargo_log="$3"
  shift 3
  local bin_dir="$TMP_ROOT/bin"
  install_cargo_shim "$bin_dir" "$cargo_log"
  : >"$cargo_log"
  mkdir -p "$output_dir"
  local status=0
  env -u QUICFUSCATE_JSON_CONTRACT_TEST \
    PATH="$bin_dir:$PATH" \
    QUICFUSCATE_CONTRACT_CARGO_LOG="$cargo_log" \
    bash "$RUNNER" --output-dir "$output_dir" "$@" >"$log_file" 2>&1 || status=$?
  printf '%s' "$status"
}

assert_python() {
  python3 - "$@" <<'PY'
import json
import sys
from pathlib import Path

mode = sys.argv[1]
canonical = ["batch", "memory", "simd", "cpu", "zero-copy", "telemetry", "integration", "stress"]

def load_items(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return document.get("items") or []

def by_name(items):
    named = {}
    for item in items:
        name = item.get("name")
        if name:
            named.setdefault(name, []).append(item)
    return named

if mode == "scopes":
    json_path, selected_csv, skip_reason, expected_mode, selected_scopes_field = sys.argv[2:7]
    selected = [] if selected_csv == "-" else selected_csv.split(",")
    items = load_items(json_path)
    named = by_name(items)
    selection = named.get("selection")
    if not selection:
        raise SystemExit(f"missing selection record in {json_path}")
    record = selection[0]
    if record.get("result") != "PASS" or record.get("reason") != "explicit_scope_selection":
        raise SystemExit(f"invalid selection record: {record}")
    if record.get("mode") != expected_mode:
        raise SystemExit(f"mode {record.get('mode')!r} != {expected_mode!r}")
    if record.get("selected_scopes") != selected_scopes_field:
        raise SystemExit(
            f"selected_scopes {record.get('selected_scopes')!r} != {selected_scopes_field!r}"
        )
    for scope in canonical:
        rows = named.get(f"scope-{scope}")
        if not rows:
            raise SystemExit(f"missing scope-{scope} in {json_path}")
        row = rows[0]
        if selected_csv == "-" or scope in selected:
            if row.get("result") != "PASS" or row.get("reason") != "selected_by_scope":
                raise SystemExit(f"scope-{scope} should be selected: {row}")
        else:
            if row.get("result") != "SKIP" or row.get("reason") != skip_reason:
                raise SystemExit(f"scope-{scope} skip mismatch: {row}")
    executed = [
        item.get("name")
        for item in items
        if item.get("name")
        and not str(item.get("name")).startswith("scope-")
        and item.get("name") != "selection"
        and item.get("name") != "json-contract-fixture"
    ]
    print("\n".join(executed))
    raise SystemExit(0)

if mode == "no_ok":
    log_path = Path(sys.argv[2])
    text = log_path.read_text(encoding="utf-8")
    if "[OK]" in text:
        raise SystemExit(f"{log_path} unexpectedly contains [OK]")
    if "[FAIL]" not in text:
        raise SystemExit(f"{log_path} missing [FAIL]")
    raise SystemExit(0)

if mode == "cargo":
    cargo_log = Path(sys.argv[2]).read_text(encoding="utf-8")
    required = sys.argv[3].split("|") if sys.argv[3] != "-" else []
    forbidden = sys.argv[4].split("|") if sys.argv[4] != "-" else []
    for token in required:
        if token not in cargo_log:
            raise SystemExit(f"cargo log missing required token {token!r}")
    for token in forbidden:
        if token in cargo_log:
            raise SystemExit(f"cargo log contains forbidden token {token!r}")
    raise SystemExit(0)

raise SystemExit(f"unknown mode {mode}")
PY
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
expect_status 2 "$TMP_ROOT/malformed.log" bash "$RUNNER" --only "batch,,cpu" --output-dir "$MALFORMED_DIR"
[[ ! -e "$MALFORMED_DIR" ]] || fail_fixture "malformed scope created an artifact directory"

COMBINED_ALL_DIR="$TMP_ROOT/invalid-all-combo"
expect_status 2 "$TMP_ROOT/all-combo.log" bash "$RUNNER" --only "all,batch" --output-dir "$COMBINED_ALL_DIR"
[[ ! -e "$COMBINED_ALL_DIR" ]] || fail_fixture "all+scope combination created an artifact directory"

TELEMETRY_DIR="$TMP_ROOT/only-telemetry"
TELEMETRY_LOG="$TMP_ROOT/only-telemetry.log"
TELEMETRY_CARGO="$TMP_ROOT/only-telemetry.cargo"
status="$(run_runner "$TELEMETRY_DIR" "$TELEMETRY_LOG" "$TELEMETRY_CARGO" --only telemetry)"
[[ "$status" == "0" ]] || fail_fixture "telemetry scope exited $status"
grep -Fq "[OK]" "$TELEMETRY_LOG" || fail_fixture "telemetry scope missing [OK]"
assert_python scopes "$TELEMETRY_DIR/results.json" telemetry not_selected_by_scope full telemetry >/dev/null
assert_python cargo "$TELEMETRY_CARGO" "--lib telemetry|--list|TELEMETRY=1" "--lib numa|--lib hugepages|--lib sse2|--lib zero_copy|optimization_stress|--test rt-"

FAST_DIR="$TMP_ROOT/fast-default"
FAST_LOG="$TMP_ROOT/fast-default.log"
FAST_CARGO="$TMP_ROOT/fast-default.cargo"
status="$(run_runner "$FAST_DIR" "$FAST_LOG" "$FAST_CARGO" --fast)"
[[ "$status" == "0" ]] || fail_fixture "unscoped fast exited $status"
assert_python scopes "$FAST_DIR/results.json" "batch,cpu,telemetry,integration" fast_profile_omits_scope fast all >/dev/null
assert_python cargo "$FAST_CARGO" \
  "--lib normalized_batch_size|--lib cpu_profile_mask|--lib test_batch_|--lib telemetry|--test rt-argsort-parity|--test rt-simd-selfcheck" \
  "--lib numa|--lib hugepages|optimization_stress|--lib zero_copy|--test rt-varint-roundtrip"

MEMORY_FAST_DIR="$TMP_ROOT/fast-only-memory"
MEMORY_FAST_LOG="$TMP_ROOT/fast-only-memory.log"
MEMORY_FAST_CARGO="$TMP_ROOT/fast-only-memory.cargo"
status="$(run_runner "$MEMORY_FAST_DIR" "$MEMORY_FAST_LOG" "$MEMORY_FAST_CARGO" --fast --only memory)"
[[ "$status" == "0" ]] || fail_fixture "fast --only memory exited $status"
assert_python scopes "$MEMORY_FAST_DIR/results.json" memory not_selected_by_scope fast memory >/dev/null
assert_python cargo "$MEMORY_FAST_CARGO" "NUMA=local|NUMA=interleave|NUMA=preferred:0|HUGEPAGE=1|--lib hugepages|--lib numa" "--lib telemetry|optimization_stress|--test rt-"

ZERO_DIR="$TMP_ROOT/only-zero-copy"
ZERO_LOG="$TMP_ROOT/only-zero-copy.log"
ZERO_CARGO="$TMP_ROOT/only-zero-copy.cargo"
status="$(run_runner "$ZERO_DIR" "$ZERO_LOG" "$ZERO_CARGO" --only zero-copy)"
[[ "$status" == "0" ]] || fail_fixture "zero-copy scope exited $status"
assert_python scopes "$ZERO_DIR/results.json" zero-copy not_selected_by_scope full zero-copy >/dev/null
assert_python cargo "$ZERO_CARGO" "--lib zero_copy|zero_copy_dgram" "--lib numa|optimization_stress|--test rt-"

FAIL_DIR="$TMP_ROOT/fail-telemetry"
FAIL_LOG="$TMP_ROOT/fail-telemetry.log"
FAIL_CARGO="$TMP_ROOT/fail-telemetry.cargo"
install_cargo_shim "$TMP_ROOT/bin" "$FAIL_CARGO"
: >"$FAIL_CARGO"
mkdir -p "$FAIL_DIR"
fail_status=0
env -u QUICFUSCATE_JSON_CONTRACT_TEST \
  PATH="$TMP_ROOT/bin:$PATH" \
  QUICFUSCATE_CONTRACT_CARGO_LOG="$FAIL_CARGO" \
  QUICFUSCATE_CONTRACT_CARGO_FAIL=1 \
  bash "$RUNNER" --only telemetry --output-dir "$FAIL_DIR" >"$FAIL_LOG" 2>&1 || fail_status=$?
[[ "$fail_status" -ne 0 ]] || fail_fixture "injected telemetry failure exited 0"
assert_python no_ok "$FAIL_LOG"
python3 - "$FAIL_DIR/results.json" <<'PY'
import json
import sys
from pathlib import Path

items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items") or []
if not any(item.get("result") == "FAIL" for item in items):
    raise SystemExit("injected failure did not record a FAIL item")
PY

python3 - "$FULL_SUITE" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
count = text.count("suites/test-optimization.sh")
if count != 2:
    raise SystemExit(
        f"full-suite utility must invoke test-optimization.sh exactly twice (scoped + default), got {count}"
    )
if "run_selected_scope" not in text or 'optimization)' not in text:
    raise SystemExit("full-suite utility lost the scoped optimization owner")
PY

echo "[PASS] optimization --only scope contract"
