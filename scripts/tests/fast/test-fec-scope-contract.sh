#!/usr/bin/env bash
# Description: Contract test: FEC --only scopes, skip evidence, and fail-closed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../lib/lib-common.sh"

RUNNER="$PROJECT_ROOT/scripts/tests/suites/test-fec.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-fec-scope.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail_fixture() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_status() {
  local expected="$1"
  local log_file="$2"
  shift 2
  local status=0
  "$@" >"$log_file" 2>&1 || status=$?
  if [[ "$status" -ne "$expected" ]]; then
    echo "Expected status $expected but got $status for: $*" >&2
    cat "$log_file" >&2
    exit 1
  fi
}

install_cargo_shim() {
  local bin_dir="$1"
  local cargo_log="$2"
  mkdir -p "$bin_dir"
  cat >"$bin_dir/cargo" <<'SH'
#!/usr/bin/env bash
log_file="${QUICFUSCATE_CONTRACT_CARGO_LOG:-/dev/null}"
# Append raw args and relevant env for inspection
printf '%s\n' "$*" >> "$log_file"
env | grep -E "^QUICFUSCATE_" >> "$log_file" 2>/dev/null || true
# Simulate cargo test output with 1 test
echo "running 1 test"
echo "test dummy ... ok"
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
    json_path, selected_csv, skip_reason, expected_effective = sys.argv[2:6]
    selected = [] if selected_csv == "-" else selected_csv.split(",")
    items = load_items(json_path)
    named = by_name(items)
    sel = named.get("selection")
    if not sel:
        raise SystemExit(f"missing selection in {json_path}")
    rec = sel[0]
    if rec.get("result") != "PASS" or rec.get("reason") != "explicit_scope_selection":
        raise SystemExit(f"bad selection record: {rec}")
    if rec.get("effective_scopes") != expected_effective:
        raise SystemExit(f"effective_scopes {rec.get('effective_scopes')!r} != {expected_effective!r}")
    canonical = ["modes","gf16","refactor"]
    for scope in canonical:
        rows = named.get(f"scope:{scope}")
        if not rows:
            raise SystemExit(f"missing scope:{scope}")
        row = rows[0]
        if scope in selected:
            if row.get("result") != "PASS" or row.get("reason") != "selected":
                raise SystemExit(f"scope:{scope} should be PASS/selected: {row}")
        else:
            if row.get("result") != "SKIP" or row.get("reason") != skip_reason:
                raise SystemExit(f"scope:{scope} skip mismatch: {row} expected {skip_reason}")
    # also check that at least one cargo: item exists for selected scopes
    print("scopes ok")
    raise SystemExit(0)

if mode == "no_ok":
    log_path = Path(sys.argv[2])
    text = log_path.read_text(encoding="utf-8")
    if "[OK]" in text:
        raise SystemExit(f"{log_path} contains [OK] unexpectedly")
    if "[FAIL]" not in text:
        raise SystemExit(f"{log_path} missing [FAIL]")
    raise SystemExit(0)

if mode == "cargo":
    cargo_log = Path(sys.argv[2]).read_text(encoding="utf-8")
    required = sys.argv[3].split("|") if sys.argv[3] != "-" else []
    forbidden = sys.argv[4].split("|") if sys.argv[4] != "-" else []
    for token in required:
        if token not in cargo_log:
            raise SystemExit(f"cargo log missing required {token!r}\n{cargo_log}")
    for token in forbidden:
        if token in cargo_log:
            raise SystemExit(f"cargo log contains forbidden {token!r}")
    raise SystemExit(0)

raise SystemExit(f"unknown mode {mode}")
PY
}

# Help
HELP_LOG="$TMP_ROOT/help.log"
expect_status 0 "$HELP_LOG" bash "$RUNNER" --help
grep -Fq "modes,gf16,refactor" "$HELP_LOG" || fail_fixture "help missing canonical scopes"
grep -Fq -- "--only" "$HELP_LOG" || fail_fixture "help missing --only"
grep -Fq -- "--refactor" "$HELP_LOG" || fail_fixture "help missing --refactor"

# Unknown scope
INVALID_DIR="$TMP_ROOT/invalid-unknown"
expect_status 2 "$TMP_ROOT/unknown.log" bash "$RUNNER" --only nope --output-dir "$INVALID_DIR"
[[ ! -e "$INVALID_DIR" ]] || fail_fixture "unknown scope created dir"

# Empty scope
EMPTY_DIR="$TMP_ROOT/invalid-empty"
expect_status 2 "$TMP_ROOT/empty.log" bash "$RUNNER" --only "" --output-dir "$EMPTY_DIR"
[[ ! -e "$EMPTY_DIR" ]] || fail_fixture "empty scope created dir"

# Malformed
MALFORMED_DIR="$TMP_ROOT/invalid-malformed"
expect_status 2 "$TMP_ROOT/malformed.log" bash "$RUNNER" --only "modes,,gf16" --output-dir "$MALFORMED_DIR"
[[ ! -e "$MALFORMED_DIR" ]] || fail_fixture "malformed scope created dir"

# Duplicate
DUP_DIR="$TMP_ROOT/invalid-dup"
expect_status 2 "$TMP_ROOT/dup.log" bash "$RUNNER" --only "modes,modes" --output-dir "$DUP_DIR"
[[ ! -e "$DUP_DIR" ]] || fail_fixture "duplicate scope created dir"

# Conflicting legacy
CONFLICT_DIR="$TMP_ROOT/invalid-conflict"
expect_status 2 "$TMP_ROOT/conflict.log" bash "$RUNNER" --only modes --refactor --output-dir "$CONFLICT_DIR"
[[ ! -e "$CONFLICT_DIR" ]] || fail_fixture "conflict created dir"
CONFLICT2_DIR="$TMP_ROOT/invalid-conflict2"
expect_status 2 "$TMP_ROOT/conflict2.log" bash "$RUNNER" --only refactor --refactor-only --output-dir "$CONFLICT2_DIR"
[[ ! -e "$CONFLICT2_DIR" ]] || fail_fixture "conflict2 created dir"

# Default compatibility (no --only, no refactor => modes,gf16)
DEFAULT_DIR="$TMP_ROOT/default"
DEFAULT_LOG="$TMP_ROOT/default.log"
DEFAULT_CARGO="$TMP_ROOT/default.cargo"
status="$(run_runner "$DEFAULT_DIR" "$DEFAULT_LOG" "$DEFAULT_CARGO")"
[[ "$status" == "0" ]] || fail_fixture "default exited $status"
grep -Fq "[OK]" "$DEFAULT_LOG" || fail_fixture "default missing [OK]"
assert_python scopes "$DEFAULT_DIR/results.json" "modes,gf16" "not_selected_by_scope" "modes,gf16"
assert_python cargo "$DEFAULT_CARGO" "QUICFUSCATE_FEC_INITIAL_MODE=zero|QUICFUSCATE_FEC_INITIAL_MODE=streaming|QUICFUSCATE_GF16_SIMD=1" "test_streaming_tetrys"

# --only modes
MODES_DIR="$TMP_ROOT/only-modes"
MODES_LOG="$TMP_ROOT/only-modes.log"
MODES_CARGO="$TMP_ROOT/only-modes.cargo"
status="$(run_runner "$MODES_DIR" "$MODES_LOG" "$MODES_CARGO" --only modes)"
[[ "$status" == "0" ]] || fail_fixture "only modes exited $status"
assert_python scopes "$MODES_DIR/results.json" "modes" "not_selected_by_scope" "modes"
assert_python cargo "$MODES_CARGO" "QUICFUSCATE_FEC_INITIAL_MODE=zero" "QUICFUSCATE_GF16_SIMD"

# --only gf16
GF16_DIR="$TMP_ROOT/only-gf16"
GF16_LOG="$TMP_ROOT/only-gf16.log"
GF16_CARGO="$TMP_ROOT/only-gf16.cargo"
status="$(run_runner "$GF16_DIR" "$GF16_LOG" "$GF16_CARGO" --only gf16)"
[[ "$status" == "0" ]] || fail_fixture "only gf16 exited $status"
assert_python scopes "$GF16_DIR/results.json" "gf16" "not_selected_by_scope" "gf16"
assert_python cargo "$GF16_CARGO" "QUICFUSCATE_GF16_SIMD=1" "QUICFUSCATE_FEC_INITIAL_MODE=zero"

# --only refactor
REFACTOR_DIR="$TMP_ROOT/only-refactor"
REFACTOR_LOG="$TMP_ROOT/only-refactor.log"
REFACTOR_CARGO="$TMP_ROOT/only-refactor.cargo"
status="$(run_runner "$REFACTOR_DIR" "$REFACTOR_LOG" "$REFACTOR_CARGO" --only refactor)"
[[ "$status" == "0" ]] || fail_fixture "only refactor exited $status"
assert_python scopes "$REFACTOR_DIR/results.json" "refactor" "not_selected_by_scope" "refactor"
assert_python cargo "$REFACTOR_CARGO" "stream_raw_roundtrip|test_batch_normal" "QUICFUSCATE_FEC_INITIAL_MODE=light"

# --only modes,gf16 explicit default
COMBO_DIR="$TMP_ROOT/combo-modes-gf16"
COMBO_LOG="$TMP_ROOT/combo.log"
COMBO_CARGO="$TMP_ROOT/combo.cargo"
status="$(run_runner "$COMBO_DIR" "$COMBO_LOG" "$COMBO_CARGO" --only modes,gf16)"
[[ "$status" == "0" ]] || fail_fixture "combo exited $status"
assert_python scopes "$COMBO_DIR/results.json" "modes,gf16" "not_selected_by_scope" "modes,gf16"

# --refactor legacy
LEGACY_DIR="$TMP_ROOT/legacy-refactor"
LEGACY_LOG="$TMP_ROOT/legacy.log"
LEGACY_CARGO="$TMP_ROOT/legacy.cargo"
status="$(run_runner "$LEGACY_DIR" "$LEGACY_LOG" "$LEGACY_CARGO" --refactor)"
[[ "$status" == "0" ]] || fail_fixture "legacy --refactor exited $status"
assert_python scopes "$LEGACY_DIR/results.json" "modes,gf16,refactor" "not_selected_by_scope" "modes,gf16,refactor"

# --refactor-only legacy
LEGACY_ONLY_DIR="$TMP_ROOT/legacy-refactor-only"
LEGACY_ONLY_LOG="$TMP_ROOT/legacy-only.log"
LEGACY_ONLY_CARGO="$TMP_ROOT/legacy-only.cargo"
status="$(run_runner "$LEGACY_ONLY_DIR" "$LEGACY_ONLY_LOG" "$LEGACY_ONLY_CARGO" --refactor-only)"
[[ "$status" == "0" ]] || fail_fixture "legacy --refactor-only exited $status"
assert_python scopes "$LEGACY_ONLY_DIR/results.json" "refactor" "not_selected_by_scope" "refactor"

# --only all => modes,gf16
ALL_DIR="$TMP_ROOT/only-all"
ALL_LOG="$TMP_ROOT/only-all.log"
ALL_CARGO="$TMP_ROOT/only-all.cargo"
status="$(run_runner "$ALL_DIR" "$ALL_LOG" "$ALL_CARGO" --only all)"
[[ "$status" == "0" ]] || fail_fixture "only all exited $status"
assert_python scopes "$ALL_DIR/results.json" "modes,gf16" "not_selected_by_scope" "modes,gf16"

# Failure propagation: inject cargo failure
FAIL_DIR="$TMP_ROOT/fail-modes"
FAIL_LOG="$TMP_ROOT/fail.log"
FAIL_CARGO="$TMP_ROOT/fail.cargo"
mkdir -p "$TMP_ROOT/bin-fail"
cat >"$TMP_ROOT/bin-fail/cargo" <<'SH'
#!/usr/bin/env bash
log_file="${QUICFUSCATE_CONTRACT_CARGO_LOG:-/dev/null}"
printf '%s\n' "$*" >> "$log_file"
echo "running 0 test"
echo "test result: ok. 0 passed"
exit 1
SH
chmod +x "$TMP_ROOT/bin-fail/cargo"
: >"$FAIL_CARGO"
mkdir -p "$FAIL_DIR"
fail_status=0
env -u QUICFUSCATE_JSON_CONTRACT_TEST \
  PATH="$TMP_ROOT/bin-fail:$PATH" \
  QUICFUSCATE_CONTRACT_CARGO_LOG="$FAIL_CARGO" \
  bash "$RUNNER" --only modes --output-dir "$FAIL_DIR" >"$FAIL_LOG" 2>&1 || fail_status=$?
[[ "$fail_status" -ne 0 ]] || fail_fixture "injected failure exited 0"
assert_python no_ok "$FAIL_LOG"
python3 - "$FAIL_DIR/results.json" <<'PY'
import json
import sys
from pathlib import Path
doc=json.loads(Path(sys.argv[1]).read_text())
items=doc["items"]
# At least one FAIL item should exist
fails=[i for i in items if i.get("result")=="FAIL"]
if not fails:
    raise SystemExit("expected FAIL item")
PY

echo "[PASS] fec --only scope contract"
