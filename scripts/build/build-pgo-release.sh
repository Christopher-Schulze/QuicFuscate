#!/usr/bin/env bash
# Description: PGO release build pipeline for the Rust binary.
set -euo pipefail

# PGO (Profile-Guided Optimization) Release Build Pipeline
# Produces an optimized binary using runtime profile data for ~10-15% perf gain.
#
# Requirements:
#   - Rust nightly or stable with LLVM PGO support
#   - llvm-profdata (ships with rustup component llvm-tools-preview)
#
# Usage:
#   ./scripts/build/build-pgo-release.sh [--features FEATURES] [--output-dir DIR] [cargo options]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Reuse the repository's artifact validation and input-boundary helpers.
# shellcheck source=../tests/lib/lib-common.sh
source "${PROJECT_ROOT}/scripts/tests/lib/lib-common.sh"

OUTPUT_ROOT="${QUICFUSCATE_PGO_OUTPUT_ROOT:-${PROJECT_ROOT}/scripts/out/build}"
EXTRA_FEATURES=""
CARGO_EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|help)
            cat <<'EOF'
Usage: build-pgo-release.sh [--features FEATURES] [--output-dir DIR] [cargo options]

Builds a profile-guided optimized release binary and writes a unique evidence
directory under scripts/out/build (or --output-dir).

Options:
  --features FEATURES  Extra cargo features; benches is always enabled.
  --output-dir DIR     Root directory for the unique PGO evidence directory.
  --                  Pass remaining arguments directly to cargo build.
EOF
            exit 0
            ;;
        --features)
            if [[ $# -lt 2 ]]; then
                die "--features requires a value"
            fi
            EXTRA_FEATURES="$2"
            shift 2
            ;;
        --features=*)
            EXTRA_FEATURES="${1#*=}"
            shift
            ;;
        --output-dir)
            if [[ $# -lt 2 ]]; then
                die "--output-dir requires a value"
            fi
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --output-dir=*)
            OUTPUT_ROOT="${1#*=}"
            shift
            ;;
        --)
            shift
            CARGO_EXTRA_ARGS+=("$@")
            break
            ;;
        --target|--target-dir|--target=*|--target-dir=*)
            die "$1 is not supported by the isolated PGO helper"
            ;;
        *)
            CARGO_EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

validate_control_free_value "PGO output directory" "$OUTPUT_ROOT" 4096
validate_feature_list "extra cargo features" "$EXTRA_FEATURES"

FEATURE_SET="benches"
if [[ -n "$EXTRA_FEATURES" ]]; then
    FEATURE_SET="${FEATURE_SET} ${EXTRA_FEATURES}"
fi

mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
RUN_TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
RUN_DIR="$(mktemp -d "${OUTPUT_ROOT}/pgo-${RUN_TIMESTAMP}-XXXXXX")"
RUN_ID="$(basename "$RUN_DIR")"
RUN_INITIALIZED=1
MANIFEST_WRITTEN=0

PGO_DIR="${RUN_DIR}/profile-data"
MERGED_PROF="${RUN_DIR}/merged.profdata"
CARGO_TARGET_DIR="${RUN_DIR}/cargo-target"
ARTIFACT_BINARY="${RUN_DIR}/quicfuscate"
MANIFEST_FILE="${RUN_DIR}/manifest.json"
WORKLOADS_FILE="${RUN_DIR}/workloads.ndjson"
LOG_DIR="${RUN_DIR}/logs"
mkdir -p "$PGO_DIR" "$LOG_DIR"
: > "$WORKLOADS_FILE"

RUSTC_BIN="${QUICFUSCATE_PGO_RUSTC:-rustc}"
CARGO_BIN="${QUICFUSCATE_PGO_CARGO:-cargo}"
LLVM_PROFDATA_BIN="${QUICFUSCATE_PGO_LLVM_PROFDATA:-}"
validate_control_free_value "rustc override" "$RUSTC_BIN" 4096
validate_control_free_value "cargo override" "$CARGO_BIN" 4096
validate_control_free_value "llvm-profdata override" "$LLVM_PROFDATA_BIN" 4096

RESULT_STATUS="FAIL"
RESULT_REASON="not-started"
CURRENT_PHASE="initialization"
SOURCE_REVISION="unknown"
SOURCE_DIRTY="unknown"
RUSTC_VERSION="unknown"
CARGO_VERSION="unknown"
LLVM_PROFDATA_VERSION="unknown"
LLVM_PROFDATA_PATH=""
INSTRUMENTED_BUILD_STATUS="NOT_RUN"
INSTRUMENTED_BUILD_RC=""
FINAL_BUILD_STATUS="NOT_RUN"
FINAL_BUILD_RC=""
PROFILE_STATUS="NOT_RUN"
PROFILE_REASON="not-run"
PROFILE_COUNT=0
PROFILE_NONEMPTY_COUNT=0
PROFILE_EMPTY_COUNT=0
MERGE_STATUS="NOT_RUN"
MERGE_REASON="not-run"
MERGE_RC=""
MERGED_PROFILE_BYTES=0
FINAL_BINARY_SHA256=""
FINAL_BINARY_BYTES=0
INSTRUMENTED_ARGV_JSON="[]"
FINAL_ARGV_JSON="[]"

if SOURCE_REVISION_VALUE="$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null)"; then
    SOURCE_REVISION="$SOURCE_REVISION_VALUE"
fi
if git -C "$PROJECT_ROOT" diff --quiet --ignore-submodules -- . && \
    git -C "$PROJECT_ROOT" diff --cached --quiet --ignore-submodules -- .; then
    SOURCE_DIRTY="false"
else
    SOURCE_DIRTY="true"
fi

pgo_command_available() {
    local command_name="$1"
    if [[ "$command_name" == */* ]]; then
        [[ -x "$command_name" ]]
    else
        command -v "$command_name" >/dev/null 2>&1
    fi
}

pgo_tool_version() {
    local command_name="$1"
    local version_output
    if version_output="$("$command_name" --version 2>&1)"; then
        printf '%s' "${version_output%%$'\n'*}"
    else
        printf 'unavailable'
    fi
}

pgo_argv_json() {
    python3 - "$@" <<'PY'
import json
import sys

print(json.dumps(sys.argv[1:], ensure_ascii=False, separators=(",", ":")))
PY
}

pgo_file_size() {
    local file="$1"
    wc -c < "$file" | tr -d '[:space:]'
}

pgo_sha256() {
    local file="$1"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        return 1
    fi
}

pgo_profile_count() {
    local mode="$1"
    python3 - "$PGO_DIR" "$mode" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
mode = sys.argv[2]
count = 0
for path in root.rglob("*.profraw"):
    if path.is_file() and (mode != "nonempty" or path.stat().st_size > 0):
        count += 1
print(count)
PY
}

pgo_profile_files_json() {
    python3 - "$PGO_DIR" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
files = []
for path in sorted(root.rglob("*.profraw")):
    if path.is_file():
        files.append({
            "path": str(path.relative_to(root)),
            "size_bytes": path.stat().st_size,
        })
print(json.dumps(files, ensure_ascii=False, separators=(",", ":")))
PY
}

pgo_refresh_profile_state() {
    PROFILE_COUNT="$(pgo_profile_count all)"
    PROFILE_NONEMPTY_COUNT="$(pgo_profile_count nonempty)"
    PROFILE_EMPTY_COUNT=$((PROFILE_COUNT - PROFILE_NONEMPTY_COUNT))
    PROFILE_FILES_JSON="$(pgo_profile_files_json)"
    if [[ -f "$MERGED_PROF" ]]; then
        MERGED_PROFILE_BYTES="$(pgo_file_size "$MERGED_PROF")"
    fi
    if [[ -f "$ARTIFACT_BINARY" ]]; then
        FINAL_BINARY_BYTES="$(pgo_file_size "$ARTIFACT_BINARY")"
        if [[ -z "$FINAL_BINARY_SHA256" ]]; then
            FINAL_BINARY_SHA256="$(pgo_sha256 "$ARTIFACT_BINARY" 2>/dev/null || true)"
        fi
    fi
}

pgo_append_workload_record() {
    local name="$1"
    local status="$2"
    local profile_status="$3"
    local exit_code="$4"
    local before_count="$5"
    local after_count="$6"
    local before_nonempty="$7"
    local after_nonempty="$8"
    local reason="$9"
    local argv_json="${10}"
    local files_json="${11}"

    python3 - "$WORKLOADS_FILE" "$name" "$status" "$profile_status" "$exit_code" \
        "$before_count" "$after_count" "$before_nonempty" "$after_nonempty" "$reason" \
        "$argv_json" "$files_json" <<'PY'
import json
from pathlib import Path
import sys

def optional_int(value):
    return None if value == "" else int(value)

record = {
    "name": sys.argv[2],
    "status": sys.argv[3],
    "profile_status": sys.argv[4],
    "exit_code": optional_int(sys.argv[5]),
    "profile_count_before": int(sys.argv[6]),
    "profile_count_after": int(sys.argv[7]),
    "nonempty_profile_count_before": int(sys.argv[8]),
    "nonempty_profile_count_after": int(sys.argv[9]),
    "reason": sys.argv[10] or None,
    "argv": json.loads(sys.argv[11]),
    "profile_files": json.loads(sys.argv[12]),
}
with Path(sys.argv[1]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
PY
}

pgo_run_workload() {
    local name="$1"
    shift
    local workload_log="${LOG_DIR}/workload-${name}.log"
    local before_count; before_count="$(pgo_profile_count all)"
    local before_nonempty; before_nonempty="$(pgo_profile_count nonempty)"
    local argv_json; argv_json="$(pgo_argv_json "$INSTRUMENTED_BINARY" "$@")"
    local workload_rc=0
    local workload_status="PASS"
    local workload_reason=""
    local profile_status="NO_DATA"
    local after_count after_nonempty files_json

    CURRENT_PHASE="profile-collection:${name}"
    if LLVM_PROFILE_FILE="${PGO_DIR}/%p-%m.profraw" "$INSTRUMENTED_BINARY" "$@" > "$workload_log" 2>&1; then
        workload_rc=0
    else
        workload_rc=$?
        workload_status="FAIL"
        workload_reason="workload-exit-${workload_rc}"
    fi
    after_count="$(pgo_profile_count all)"
    after_nonempty="$(pgo_profile_count nonempty)"
    files_json="$(pgo_profile_files_json)"
    if (( after_nonempty > before_nonempty )); then
        profile_status="PASS"
    fi

    if ! pgo_append_workload_record "$name" "$workload_status" "$profile_status" \
        "$workload_rc" "$before_count" "$after_count" "$before_nonempty" "$after_nonempty" \
        "$workload_reason" "$argv_json" "$files_json"; then
        LAST_WORKLOAD_STATUS="FAIL"
        LAST_WORKLOAD_REASON="workload-record-write-failed"
        return 1
    fi
    LAST_WORKLOAD_STATUS="$workload_status"
    LAST_WORKLOAD_REASON="$workload_reason"
    return 0
}

pgo_record_unavailable_workload() {
    local name="$1"
    local reason="$2"
    shift 2
    local argv_json; argv_json="$(pgo_argv_json "$INSTRUMENTED_BINARY" "$@")"
    local profile_count; profile_count="$(pgo_profile_count all)"
    local profile_nonempty; profile_nonempty="$(pgo_profile_count nonempty)"
    if ! pgo_append_workload_record "$name" "UNAVAILABLE" "NOT_RUN" "" \
        "$profile_count" "$profile_count" "$profile_nonempty" "$profile_nonempty" \
        "$reason" "$argv_json" "[]"; then
        LAST_WORKLOAD_STATUS="FAIL"
        LAST_WORKLOAD_REASON="workload-record-write-failed"
        return 1
    fi
    LAST_WORKLOAD_STATUS="UNAVAILABLE"
    LAST_WORKLOAD_REASON="$reason"
    return 0
}

pgo_write_manifest() {
    pgo_refresh_profile_state
    local manifest_raw
    if ! manifest_raw="$(python3 - "$MANIFEST_FILE" "$RUN_ID" "$RUN_DIR" "$PROJECT_ROOT" \
        "$RESULT_STATUS" "$RESULT_REASON" "$RUN_TIMESTAMP" "$SOURCE_REVISION" "$SOURCE_DIRTY" \
        "$FEATURE_SET" "$RUSTC_VERSION" "$CARGO_VERSION" "$LLVM_PROFDATA_VERSION" \
        "$LLVM_PROFDATA_PATH" "$INSTRUMENTED_BUILD_STATUS" "$INSTRUMENTED_BUILD_RC" \
        "$FINAL_BUILD_STATUS" "$FINAL_BUILD_RC" "$PROFILE_STATUS" "$PROFILE_REASON" \
        "$PROFILE_COUNT" "$PROFILE_NONEMPTY_COUNT" "$PROFILE_EMPTY_COUNT" "$MERGE_STATUS" \
        "$MERGE_REASON" "$MERGE_RC" "$MERGED_PROF" "$MERGED_PROFILE_BYTES" \
        "$ARTIFACT_BINARY" "$FINAL_BINARY_SHA256" "$FINAL_BINARY_BYTES" \
        "$INSTRUMENTED_ARGV_JSON" "$FINAL_ARGV_JSON" "$WORKLOADS_FILE" "$PGO_DIR" \
        "$LOG_DIR" "$CARGO_TARGET_DIR" <<'PY'
import json
import re
from pathlib import Path
import sys

(
    manifest_file, run_id, run_dir, project_root, result_status, result_reason,
    run_timestamp, source_revision, source_dirty, feature_set, rustc_version,
    cargo_version, llvm_profdata_version, llvm_profdata_path, instrumented_status,
    instrumented_rc, final_status, final_rc, profile_status, profile_reason,
    profile_count, profile_nonempty_count, profile_empty_count, merge_status,
    merge_reason, merge_rc, merged_profile, merged_profile_bytes, artifact_binary,
    final_sha256, final_binary_bytes, instrumented_argv, final_argv,
    workloads_file, profile_dir, log_dir, cargo_target_dir,
) = sys.argv[1:]

def optional_int(value):
    return None if value == "" else int(value)

def parse_json(value):
    return json.loads(value)

workloads = []
workload_path = Path(workloads_file)
if workload_path.exists():
    for line in workload_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            workloads.append(json.loads(line))

profile_root = Path(profile_dir)
profile_files = []
for path in sorted(profile_root.rglob("*.profraw")):
    if path.is_file():
        profile_files.append({
            "path": str(path.relative_to(profile_root)),
            "size_bytes": path.stat().st_size,
        })

log_root = Path(log_dir)
logs = []
if log_root.exists():
    logs = [
        str(path.relative_to(Path(run_dir)))
        for path in sorted(log_root.rglob("*"))
        if path.is_file()
    ]

features = [item for item in re.split(r"[\\s,]+", feature_set.strip()) if item]
manifest = {
    "schema": "quicfuscate.pgo-release.v1",
    "tool": "quicfuscate",
    "timestamp_utc": run_timestamp,
    "status": result_status,
    "reason": result_reason,
    "run_id": run_id,
    "artifact": {
        "run_id": run_id,
        "path": str(Path(manifest_file).resolve()),
        "ownership": "create-new",
        "replacement": "create-new",
        "source_revision": source_revision,
    },
    "source": {
        "project_root": str(Path(project_root).resolve()),
        "revision": source_revision,
        "dirty": source_dirty == "true",
    },
    "features": {
        "cargo": features,
        "raw": feature_set,
    },
    "toolchain": {
        "rustc": rustc_version,
        "cargo": cargo_version,
        "llvm_profdata": llvm_profdata_version,
        "llvm_profdata_path": llvm_profdata_path or None,
    },
    "commands": {
        "instrumented_build": {
            "argv": parse_json(instrumented_argv),
            "env": {
                "CARGO_TARGET_DIR": cargo_target_dir,
                "RUSTFLAGS": f"-Cprofile-generate={profile_dir}",
            },
        },
        "final_build": {
            "argv": parse_json(final_argv),
            "env": {
                "CARGO_TARGET_DIR": cargo_target_dir,
                "RUSTFLAGS": f"-Cprofile-use={merged_profile} -Cllvm-args=-pgo-warn-missing-function",
            },
        },
    },
    "workloads": workloads,
    "profile_collection": {
        "directory": str(profile_root.resolve()),
        "status": profile_status,
        "reason": profile_reason,
        "count": int(profile_count),
        "nonempty_count": int(profile_nonempty_count),
        "empty_count": int(profile_empty_count),
        "files": profile_files,
    },
    "merge": {
        "status": merge_status,
        "reason": merge_reason,
        "exit_code": optional_int(merge_rc),
        "path": str(Path(merged_profile).resolve()),
        "size_bytes": int(merged_profile_bytes),
    },
    "final_build": {
        "status": final_status,
        "exit_code": optional_int(final_rc),
        "binary": str(Path(artifact_binary).resolve()),
        "size_bytes": int(final_binary_bytes),
        "sha256": final_sha256 or None,
    },
    "diagnostics": {
        "retained": True,
        "run_directory": str(Path(run_dir).resolve()),
        "logs": logs,
    },
}
print(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))
PY
)"; then
        return 1
    fi
    qf_json_write_raw_file "$MANIFEST_FILE" "$manifest_raw"
}

pgo_on_exit() {
    local exit_status="$1"
    if [[ "$exit_status" -ne 0 && "$RESULT_STATUS" == "PASS" ]]; then
        RESULT_STATUS="FAIL"
        RESULT_REASON="${CURRENT_PHASE}-exit-${exit_status}"
    fi
    if [[ "$RUN_INITIALIZED" == "1" && "$MANIFEST_WRITTEN" == "0" ]]; then
        MANIFEST_WRITTEN=1
        if ! pgo_write_manifest; then
            error "could not write PGO manifest: ${MANIFEST_FILE}"
            if [[ "$exit_status" -eq 0 ]]; then
                exit_status=1
            fi
        fi
    fi
    if [[ "$exit_status" -eq 0 ]]; then
        echo "PGO evidence: ${RUN_DIR}"
    else
        error "PGO run ${RUN_ID} ended with ${RESULT_STATUS}: ${RESULT_REASON}"
        echo "PGO diagnostics retained: ${RUN_DIR}" >&2
    fi
    return "$exit_status"
}

trap 'pgo_on_exit "$?"' EXIT

INSTRUMENTED_BINARY="${CARGO_TARGET_DIR}/release/quicfuscate"
CARGO_BUILD_ARGS=(build --release --features "$FEATURE_SET" "${CARGO_EXTRA_ARGS[@]}")
INSTRUMENTED_ARGV_JSON="$(pgo_argv_json "$CARGO_BIN" "${CARGO_BUILD_ARGS[@]}")"
FINAL_ARGV_JSON="$INSTRUMENTED_ARGV_JSON"

if ! pgo_command_available "$RUSTC_BIN"; then
    RESULT_STATUS="UNAVAILABLE"
    RESULT_REASON="rustc-missing"
    CURRENT_PHASE="preflight"
    exit 1
fi
if ! pgo_command_available "$CARGO_BIN"; then
    RESULT_STATUS="UNAVAILABLE"
    RESULT_REASON="cargo-missing"
    CURRENT_PHASE="preflight"
    exit 1
fi
RUSTC_VERSION="$(pgo_tool_version "$RUSTC_BIN")"
CARGO_VERSION="$(pgo_tool_version "$CARGO_BIN")"

if [[ -n "$LLVM_PROFDATA_BIN" ]]; then
    if pgo_command_available "$LLVM_PROFDATA_BIN"; then
        LLVM_PROFDATA_PATH="$LLVM_PROFDATA_BIN"
    else
        RESULT_STATUS="UNAVAILABLE"
        RESULT_REASON="llvm-profdata-missing"
        CURRENT_PHASE="preflight"
        exit 1
    fi
else
    SYSROOT_LOG="${LOG_DIR}/rustc-sysroot.log"
    if SYSROOT="$("$RUSTC_BIN" --print sysroot 2> "$SYSROOT_LOG")"; then
        LLVM_PROFDATA_PATH="$(find "${SYSROOT}/lib" -type f -name llvm-profdata -perm -111 -print -quit 2>/dev/null)"
    fi
    if [[ -z "$LLVM_PROFDATA_PATH" ]]; then
        RESULT_STATUS="UNAVAILABLE"
        RESULT_REASON="llvm-profdata-missing"
        CURRENT_PHASE="preflight"
        exit 1
    fi
fi
LLVM_PROFDATA_VERSION="$(pgo_tool_version "$LLVM_PROFDATA_PATH")"

echo "=== QuicFuscate PGO Release Build ==="
echo "Evidence directory: ${RUN_DIR}"
echo "Profile data dir:   ${PGO_DIR}"
echo "llvm-profdata:      ${LLVM_PROFDATA_PATH}"
echo "Features:            ${FEATURE_SET}"
echo

CURRENT_PHASE="instrumented-build"
echo "--- Step 1/4: Instrumented build ---"
INSTRUMENTED_BUILD_STATUS="RUNNING"
if CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    RUSTFLAGS="-Cprofile-generate=${PGO_DIR}" \
    "$CARGO_BIN" "${CARGO_BUILD_ARGS[@]}" > "${LOG_DIR}/instrumented-build.log" 2>&1; then
    INSTRUMENTED_BUILD_STATUS="PASS"
    INSTRUMENTED_BUILD_RC=0
else
    INSTRUMENTED_BUILD_RC=$?
    INSTRUMENTED_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="instrumented-build-failed"
    exit 1
fi
if [[ ! -x "$INSTRUMENTED_BINARY" ]]; then
    INSTRUMENTED_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="instrumented-binary-missing"
    exit 1
fi
echo "Instrumented binary built: ${INSTRUMENTED_BINARY}"

CURRENT_PHASE="profile-collection"
echo
echo "--- Step 2/4: Collect profile data ---"
if ! pgo_run_workload help --help; then
    RESULT_STATUS="FAIL"
    RESULT_REASON="workload-record-failed"
    exit 1
fi
if [[ "$LAST_WORKLOAD_STATUS" != "PASS" ]]; then
    RESULT_STATUS="FAIL"
    RESULT_REASON="required-help-workload-failed"
    exit 1
fi

HELP_LOG="${LOG_DIR}/workload-help.log"
if grep -q 'pool-bench' "$HELP_LOG"; then
    if ! pgo_run_workload pool-bench pool-bench --iterations 500 --payload 1400 --warmup 50 --json; then
        RESULT_STATUS="FAIL"
        RESULT_REASON="workload-record-failed"
        exit 1
    fi
else
    if ! pgo_record_unavailable_workload pool-bench subcommand-not-advertised pool-bench; then
        RESULT_STATUS="FAIL"
        RESULT_REASON="workload-record-failed"
        exit 1
    fi
fi
if [[ "$LAST_WORKLOAD_STATUS" == "FAIL" ]]; then
    RESULT_STATUS="FAIL"
    RESULT_REASON="pool-bench-failed"
    exit 1
fi

if grep -q 'crypto-bench' "$HELP_LOG"; then
    if ! pgo_run_workload crypto-bench crypto-bench --iterations 500 --payload 1400 --warmup 50 --json; then
        RESULT_STATUS="FAIL"
        RESULT_REASON="workload-record-failed"
        exit 1
    fi
else
    if ! pgo_record_unavailable_workload crypto-bench subcommand-not-advertised crypto-bench; then
        RESULT_STATUS="FAIL"
        RESULT_REASON="workload-record-failed"
        exit 1
    fi
fi
if [[ "$LAST_WORKLOAD_STATUS" == "FAIL" ]]; then
    RESULT_STATUS="FAIL"
    RESULT_REASON="crypto-bench-failed"
    exit 1
fi

pgo_refresh_profile_state
if (( PROFILE_COUNT == 0 )); then
    PROFILE_STATUS="FAIL"
    PROFILE_REASON="no-profile-output"
    RESULT_STATUS="FAIL"
    RESULT_REASON="no-profile-output"
    exit 1
fi
if (( PROFILE_EMPTY_COUNT > 0 )); then
    PROFILE_STATUS="FAIL"
    PROFILE_REASON="empty-profile-file"
    RESULT_STATUS="FAIL"
    RESULT_REASON="empty-profile-file"
    exit 1
fi
PROFILE_STATUS="PASS"
PROFILE_REASON="nonempty-profile-files-collected"
echo "Profile files collected: ${PROFILE_NONEMPTY_COUNT}"

CURRENT_PHASE="profile-merge"
echo
echo "--- Step 3/4: Merge profile data ---"
MERGE_STATUS="RUNNING"
PROFILE_ARGS=()
while IFS= read -r profile_file; do
    [[ -n "$profile_file" ]] && PROFILE_ARGS+=("$profile_file")
done < <(find "$PGO_DIR" -type f -name '*.profraw' -size +0c -print | sort)
if [[ "${#PROFILE_ARGS[@]}" -eq 0 ]]; then
    MERGE_STATUS="FAIL"
    MERGE_REASON="no-nonempty-profile-files"
    RESULT_STATUS="FAIL"
    RESULT_REASON="no-nonempty-profile-files"
    exit 1
fi
if "$LLVM_PROFDATA_PATH" merge -o "$MERGED_PROF" "${PROFILE_ARGS[@]}" > "${LOG_DIR}/merge.log" 2>&1; then
    MERGE_RC=0
else
    MERGE_RC=$?
    MERGE_STATUS="FAIL"
    MERGE_REASON="llvm-profdata-merge-failed"
    RESULT_STATUS="FAIL"
    RESULT_REASON="llvm-profdata-merge-failed"
    exit 1
fi
if [[ ! -s "$MERGED_PROF" ]]; then
    MERGE_STATUS="FAIL"
    MERGE_REASON="empty-merged-profile"
    RESULT_STATUS="FAIL"
    RESULT_REASON="empty-merged-profile"
    exit 1
fi
if "$LLVM_PROFDATA_PATH" show "$MERGED_PROF" > "${LOG_DIR}/merge-validate.log" 2>&1; then
    MERGE_STATUS="PASS"
    MERGE_REASON="merged-and-validated"
else
    MERGE_STATUS="FAIL"
    MERGE_REASON="merged-profile-validation-failed"
    RESULT_STATUS="FAIL"
    RESULT_REASON="merged-profile-validation-failed"
    exit 1
fi
MERGED_PROFILE_BYTES="$(pgo_file_size "$MERGED_PROF")"
echo "Merged profile: ${MERGED_PROF}"

CURRENT_PHASE="final-build"
echo
echo "--- Step 4/4: PGO-optimized release build ---"
FINAL_BUILD_STATUS="RUNNING"
if CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    RUSTFLAGS="-Cprofile-use=${MERGED_PROF} -Cllvm-args=-pgo-warn-missing-function" \
    "$CARGO_BIN" "${CARGO_BUILD_ARGS[@]}" > "${LOG_DIR}/final-build.log" 2>&1; then
    FINAL_BUILD_STATUS="PASS"
    FINAL_BUILD_RC=0
else
    FINAL_BUILD_RC=$?
    FINAL_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="final-build-failed"
    exit 1
fi
if [[ ! -x "$INSTRUMENTED_BINARY" ]]; then
    FINAL_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="final-binary-missing"
    exit 1
fi

COPY_TMP="$(mktemp "${RUN_DIR}/quicfuscate.tmp.XXXXXX")"
if ! cp -p "$INSTRUMENTED_BINARY" "$COPY_TMP"; then
    rm -f -- "$COPY_TMP"
    FINAL_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="final-artifact-copy-failed"
    exit 1
fi
chmod +x "$COPY_TMP"
if [[ -e "$ARTIFACT_BINARY" || -L "$ARTIFACT_BINARY" ]]; then
    rm -f -- "$COPY_TMP"
    FINAL_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="final-artifact-path-exists"
    exit 1
fi
mv -- "$COPY_TMP" "$ARTIFACT_BINARY"
FINAL_BINARY_BYTES="$(pgo_file_size "$ARTIFACT_BINARY")"
FINAL_BINARY_SHA256="$(pgo_sha256 "$ARTIFACT_BINARY")"
if ! [[ "$FINAL_BINARY_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    FINAL_BUILD_STATUS="FAIL"
    RESULT_STATUS="FAIL"
    RESULT_REASON="final-binary-hash-invalid"
    exit 1
fi

RESULT_STATUS="PASS"
RESULT_REASON="complete"
CURRENT_PHASE="complete"
echo
echo "=== PGO build complete ==="
echo "Binary: ${ARTIFACT_BINARY}"
echo "Manifest: ${MANIFEST_FILE}"
