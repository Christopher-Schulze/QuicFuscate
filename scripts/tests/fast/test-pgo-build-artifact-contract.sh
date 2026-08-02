#!/usr/bin/env bash
# Description: Contract test for isolated PGO evidence and failure classification.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quicfuscate-pgo-contract.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

FAKE_ROOT="$TMP_ROOT/fake-toolchain"
FAKE_SYSROOT="$FAKE_ROOT/sysroot"
MISSING_SYSROOT="$FAKE_ROOT/sysroot-missing"
FAKE_RUSTC="$FAKE_ROOT/rustc"
FAKE_CARGO="$FAKE_ROOT/cargo"
FAKE_BINARY="$FAKE_ROOT/quicfuscate"
FAKE_LLVM_PROFDATA="$FAKE_SYSROOT/lib/llvm-profdata"
mkdir -p "$FAKE_SYSROOT/lib" "$MISSING_SYSROOT/lib"

python3 - "$FAKE_RUSTC" "$FAKE_CARGO" "$FAKE_BINARY" "$FAKE_LLVM_PROFDATA" <<'PY'
from pathlib import Path
import sys

rustc_path, cargo_path, binary_path, llvm_path = map(Path, sys.argv[1:])

rustc_path.write_text(
    '''#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  --version) printf '%s\\n' 'rustc fake-pgo 1.0.0';;
  --print) [[ "${2:-}" == sysroot ]] && printf '%s\\n' "${FAKE_SYSROOT:?}";;
  *) exit 2;;
esac
''',
    encoding="utf-8",
)

cargo_path.write_text(
    '''#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf '%s\\n' 'cargo fake-pgo 1.0.0'
  exit 0
fi
[[ "${1:-}" == build ]] || exit 2
target_dir="${CARGO_TARGET_DIR:?}"
mkdir -p "$target_dir/release"
binary="$target_dir/release/quicfuscate"
cp -p "${FAKE_BINARY:?}" "$binary"
chmod +x "$binary"
''',
    encoding="utf-8",
)

llvm_path.write_text(
    '''#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  --version) printf '%s\\n' 'llvm-profdata fake-pgo 1.0.0';;
  merge)
    [[ "${FAKE_PGO_MERGE_FAIL:-0}" != 1 ]] || exit 17
    output=''
    shift
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == -o ]]; then output="$2"; shift 2; else shift; fi
    done
    [[ -n "$output" ]] || exit 18
    printf '%s\\n' 'fake-merged-profdata' > "$output"
    ;;
  show)
    [[ -s "${2:?}" ]] || exit 19
    printf '%s\\n' 'fake profile summary';
    ;;
  *) exit 2;;
esac
''',
    encoding="utf-8",
)

binary_path.write_text(
    '''#!/usr/bin/env bash
set -Eeuo pipefail
if [[ -n "${LLVM_PROFILE_FILE:-}" && "${FAKE_PGO_NO_PROFILE:-0}" != 1 ]]; then
  profile_file="${LLVM_PROFILE_FILE//%p/$$}"
  profile_file="${profile_file//%m/fake-quicfuscate}"
  mkdir -p "$(dirname "$profile_file")"
  if [[ "${FAKE_PGO_EMPTY_PROFILE:-0}" == 1 ]]; then
    : > "$profile_file"
  else
    printf '%s\\n' 'fake-profraw' > "$profile_file"
  fi
fi
case "${1:-}" in
  --help) printf '%s\\n' 'Usage: quicfuscate [pool-bench] [crypto-bench]';;
  pool-bench|crypto-bench) printf '%s\\n' 'fake benchmark';;
  *) exit 0;;
esac
''',
    encoding="utf-8",
)

for path in (rustc_path, cargo_path, binary_path, llvm_path):
    path.chmod(0o755)
PY

export FAKE_SYSROOT
export FAKE_BINARY
export QUICFUSCATE_PGO_RUSTC="$FAKE_RUSTC"
export QUICFUSCATE_PGO_CARGO="$FAKE_CARGO"

run_helper() {
  local output_root="$1"
  local log_file="$2"
  local status
  if "$PROJECT_ROOT/scripts/build/build-pgo-release.sh" --output-dir "$output_root" > "$log_file" 2>&1; then
    status=0
  else
    status=$?
  fi
  printf '%s' "$status"
}

manifest_for() {
  find "$1" -type f -name manifest.json -print -quit
}

assert_manifest() {
  local manifest_file="$1"
  local expected_status="$2"
  local expected_reason="$3"
  python3 - "$manifest_file" "$expected_status" "$expected_reason" <<'PY'
import json
import re
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["schema"] == "quicfuscate.pgo-release.v1", document
assert document["status"] == sys.argv[2], document
assert document["reason"] == sys.argv[3], document
assert document["artifact"]["ownership"] == "create-new", document
assert document["artifact"]["run_id"] == document["run_id"], document
assert document["source"]["revision"], document
assert isinstance(document["features"]["cargo"], list), document
assert isinstance(document["toolchain"]["rustc"], str), document
assert isinstance(document["workloads"], list), document
PY
}

if rg -n 'pgo-data-quicfuscate|rm -rf "\$\{PGO_DIR\}"' \
  "$PROJECT_ROOT/scripts/build/build-pgo-release.sh"; then
  echo "fixed or destructive global PGO profile handling remains" >&2
  exit 1
fi

MISSING_ROOT="$TMP_ROOT/missing-llvm"
missing_rc="$(FAKE_SYSROOT="$MISSING_SYSROOT" run_helper "$MISSING_ROOT" "$TMP_ROOT/missing.log")"
missing_manifest="$(manifest_for "$MISSING_ROOT")"
[[ "$missing_rc" -ne 0 ]] || { echo "missing llvm-profdata unexpectedly passed" >&2; exit 1; }
assert_manifest "$missing_manifest" UNAVAILABLE llvm-profdata-missing

NO_PROFILE_ROOT="$TMP_ROOT/no-profile"
no_profile_rc="$(FAKE_PGO_NO_PROFILE=1 run_helper "$NO_PROFILE_ROOT" "$TMP_ROOT/no-profile.log")"
no_profile_manifest="$(manifest_for "$NO_PROFILE_ROOT")"
[[ "$no_profile_rc" -ne 0 ]] || { echo "no-profile fixture unexpectedly passed" >&2; exit 1; }
assert_manifest "$no_profile_manifest" FAIL no-profile-output
python3 - "$no_profile_manifest" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["profile_collection"]["status"] == "FAIL", document
assert document["profile_collection"]["count"] == 0, document
assert document["merge"]["status"] == "NOT_RUN", document
PY

EMPTY_PROFILE_ROOT="$TMP_ROOT/empty-profile"
empty_profile_rc="$(FAKE_PGO_EMPTY_PROFILE=1 run_helper "$EMPTY_PROFILE_ROOT" "$TMP_ROOT/empty-profile.log")"
empty_profile_manifest="$(manifest_for "$EMPTY_PROFILE_ROOT")"
[[ "$empty_profile_rc" -ne 0 ]] || { echo "empty-profile fixture unexpectedly passed" >&2; exit 1; }
assert_manifest "$empty_profile_manifest" FAIL empty-profile-file
python3 - "$empty_profile_manifest" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["profile_collection"]["count"] > 0, document
assert document["profile_collection"]["empty_count"] > 0, document
assert document["profile_collection"]["status"] == "FAIL", document
PY

MERGE_FAIL_ROOT="$TMP_ROOT/merge-fail"
merge_fail_rc="$(FAKE_PGO_MERGE_FAIL=1 run_helper "$MERGE_FAIL_ROOT" "$TMP_ROOT/merge-fail.log")"
merge_fail_manifest="$(manifest_for "$MERGE_FAIL_ROOT")"
[[ "$merge_fail_rc" -ne 0 ]] || { echo "merge failure fixture unexpectedly passed" >&2; exit 1; }
assert_manifest "$merge_fail_manifest" FAIL llvm-profdata-merge-failed
python3 - "$merge_fail_manifest" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["profile_collection"]["status"] == "PASS", document
assert document["profile_collection"]["nonempty_count"] > 0, document
assert document["merge"]["status"] == "FAIL", document
assert document["final_build"]["status"] == "NOT_RUN", document
PY

CONCURRENT_ROOT="$TMP_ROOT/concurrent"
mkdir -p "$CONCURRENT_ROOT"
FAKE_PGO_NO_PROFILE=0 FAKE_PGO_MERGE_FAIL=0 run_helper "$CONCURRENT_ROOT" "$TMP_ROOT/concurrent-a.log" > "$TMP_ROOT/concurrent-a.rc" &
pid_a=$!
FAKE_PGO_NO_PROFILE=0 FAKE_PGO_MERGE_FAIL=0 run_helper "$CONCURRENT_ROOT" "$TMP_ROOT/concurrent-b.log" > "$TMP_ROOT/concurrent-b.rc" &
pid_b=$!
if wait "$pid_a"; then :; else :; fi
if wait "$pid_b"; then :; else :; fi
concurrent_a_rc="$(<"$TMP_ROOT/concurrent-a.rc")"
concurrent_b_rc="$(<"$TMP_ROOT/concurrent-b.rc")"
[[ "$concurrent_a_rc" == 0 && "$concurrent_b_rc" == 0 ]] || {
  echo "concurrent PGO fixtures failed: $concurrent_a_rc/$concurrent_b_rc" >&2
  exit 1
}
python3 - "$CONCURRENT_ROOT" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifests = sorted(root.glob("pgo-*/manifest.json"))
assert len(manifests) == 2, manifests
run_ids = set()
profile_dirs = set()
for manifest_path in manifests:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert document["status"] == "PASS", document
    assert document["run_id"] not in run_ids, document
    run_ids.add(document["run_id"])
    profile_dir = Path(document["profile_collection"]["directory"]).resolve()
    assert profile_dir.is_relative_to(manifest_path.parent.resolve()), (profile_dir, manifest_path)
    assert document["profile_collection"]["nonempty_count"] > 0, document
    assert document["merge"]["status"] == "PASS", document
    assert document["final_build"]["sha256"] and len(document["final_build"]["sha256"]) == 64, document
    profile_dirs.add(str(profile_dir))
assert len(profile_dirs) == 2, profile_dirs
PY

echo "[PASS] PGO artifact contract: missing tool, empty profiles, no data, merge failure, and concurrent isolation"
