#!/usr/bin/env bash
# Description: PGO build pipeline driven by the real TUN dataplane workload.
set -euo pipefail

# Dataplane-shaped PGO: unlike build-pgo-release.sh (microbench workloads:
# pool/crypto/fec), this profiles the instrumented binary while it runs the
# actual TUN data-plane scenario (profiling-tun-mode.sh) so branch data covers
# recv/parse/encrypt/GSO/TUN, not only library benches.
#
# Flow:
#   1. instrumented build  (-Cprofile-generate, isolated target dir)
#   2. dataplane workload  (profiling-tun-mode.sh with LLVM_PROFILE_FILE; the
#                           env var propagates through `ip netns exec env` into
#                           both endpoints; SIGTERM stop => clean exit => profraw)
#   3. llvm-profdata merge
#   4. optimized build     (-Cprofile-use, isolated target dir)
#
# Requirements: Linux root for the TUN scenario, llvm-tools component
# (rustup component add llvm-tools).
#
# Usage:
#   ./scripts/build/pgo-dataplane.sh [--scenario g] [--duration 20] \
#       [--cert C --key K] [--ca CA] [--output-dir DIR] [--skip-final]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUTPUT_ROOT="${QUICFUSCATE_PGO_OUTPUT_ROOT:-${PROJECT_ROOT}/scripts/out/build}"
SCENARIO="g"
DURATION="20"
CERT=""
KEY=""
CA=""
SKIP_FINAL=0

die() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            sed -n '2,30p' "$0"; exit 0;;
        --scenario) SCENARIO="$2"; shift 2;;
        --duration) DURATION="$2"; shift 2;;
        --cert) CERT="$2"; shift 2;;
        --key) KEY="$2"; shift 2;;
        --ca) CA="$2"; shift 2;;
        --output-dir) OUTPUT_ROOT="$2"; shift 2;;
        --skip-final) SKIP_FINAL=1; shift;;
        *) die "unknown argument: $1";;
    esac
done

CARGO_BIN="${QUICFUSCATE_PGO_CARGO:-cargo}"
RUSTC_BIN="${QUICFUSCATE_PGO_RUSTC:-rustc}"
command -v "$CARGO_BIN" >/dev/null || die "cargo missing"
command -v "$RUSTC_BIN" >/dev/null || die "rustc missing"

SYSROOT="$("$RUSTC_BIN" --print sysroot)"
LLVM_PROFDATA="${QUICFUSCATE_PGO_LLVM_PROFDATA:-}"
if [[ -z "$LLVM_PROFDATA" ]]; then
    LLVM_PROFDATA="$(find "${SYSROOT}/lib" -type f -name llvm-profdata -perm -111 -print -quit 2>/dev/null)"
fi
[[ -n "$LLVM_PROFDATA" && -x "$LLVM_PROFDATA" ]] || \
    die "llvm-profdata missing (rustup component add llvm-tools)"

SCENARIO_SCRIPT="${PROJECT_ROOT}/scripts/benchmarks/profiling-tun-mode.sh"
[[ -x "$SCENARIO_SCRIPT" || -f "$SCENARIO_SCRIPT" ]] || \
    die "profiling-tun-mode.sh not found at ${SCENARIO_SCRIPT}"

mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
RUN_DIR="$(mktemp -d "${OUTPUT_ROOT}/pgo-dp-$(date -u '+%Y%m%dT%H%M%SZ')-XXXXXX")"
PGO_DIR="${RUN_DIR}/profile-data"
INSTR_TARGET="${RUN_DIR}/instr-target"
FINAL_TARGET="${RUN_DIR}/final-target"
MERGED="${RUN_DIR}/merged.profdata"
ARTIFACT="${RUN_DIR}/quicfuscate-pgo"
mkdir -p "$PGO_DIR"
# The server endpoint drops privileges to the quicfuscate user mid-scenario;
# the profile dir must stay writable for every instrumented process.
chmod 777 "$PGO_DIR"

echo "=== QuicFuscate dataplane PGO ==="
echo "Evidence dir: ${RUN_DIR}"
echo "Scenario:     ${SCENARIO} (${DURATION}s)"
echo "llvm-profdata: ${LLVM_PROFDATA}"
echo

echo "--- 1/4: instrumented build ---"
CARGO_TARGET_DIR="$INSTR_TARGET" \
    RUSTFLAGS="-Cprofile-generate=${PGO_DIR}" \
    "$CARGO_BIN" build --release --bin quicfuscate \
    > "${RUN_DIR}/instr-build.log" 2>&1 \
    || die "instrumented build failed (see ${RUN_DIR}/instr-build.log)"
INSTR_BIN="${INSTR_TARGET}/release/quicfuscate"
[[ -x "$INSTR_BIN" ]] || die "instrumented binary missing at ${INSTR_BIN}"
echo "instrumented: ${INSTR_BIN}"

echo
echo "--- 2/4: dataplane workload (scenario ${SCENARIO}) ---"
scenario_args=(--scenario "$SCENARIO" --duration "$DURATION" --binary "$INSTR_BIN"
               --project-root "$PROJECT_ROOT")
[[ -n "$CERT" ]] && scenario_args+=(--cert "$CERT")
[[ -n "$KEY" ]] && scenario_args+=(--key "$KEY")
# profiling-tun-mode.sh accepts --cert/--key/--ca via env too; --ca is not a
# CLI flag there, pass through its env var when provided.
if [[ -n "$CA" ]]; then
    export QF_PROFILE_CA_CERT="$CA"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    env LLVM_PROFILE_FILE="${PGO_DIR}/%p-%m.profraw" \
        bash "$SCENARIO_SCRIPT" "${scenario_args[@]}" \
        > "${RUN_DIR}/workload.log" 2>&1 || true
else
    sudo env LLVM_PROFILE_FILE="${PGO_DIR}/%p-%m.profraw" \
        bash "$SCENARIO_SCRIPT" "${scenario_args[@]}" \
        > "${RUN_DIR}/workload.log" 2>&1 || true
fi

mapfile -t PROFS < <(find "$PGO_DIR" -type f -name '*.profraw' -size +0c | sort)
if [[ "${#PROFS[@]}" -eq 0 ]]; then
    die "no .profraw collected — see ${RUN_DIR}/workload.log"
fi
echo "profile files: ${#PROFS[@]}"

echo
echo "--- 3/4: merge ---"
"$LLVM_PROFDATA" merge -o "$MERGED" "${PROFS[@]}" \
    || die "llvm-profdata merge failed"
"$LLVM_PROFDATA" show "$MERGED" > "${RUN_DIR}/merge-validate.log" 2>&1 \
    || die "merged profile failed validation"
echo "merged: ${MERGED} ($(wc -c < "$MERGED" | tr -d ' ') bytes)"

if [[ "$SKIP_FINAL" -eq 1 ]]; then
    echo
    echo "skip-final: profile collected+merged only"
    echo "rebuild with: RUSTFLAGS=\"-Cprofile-use=${MERGED}\" cargo build --release"
    exit 0
fi

echo
echo "--- 4/4: PGO-optimized release build ---"
CARGO_TARGET_DIR="$FINAL_TARGET" \
    RUSTFLAGS="-Cprofile-use=${MERGED} -Cllvm-args=-pgo-warn-missing-function" \
    "$CARGO_BIN" build --release --bin quicfuscate \
    > "${RUN_DIR}/final-build.log" 2>&1 \
    || die "final build failed (see ${RUN_DIR}/final-build.log)"
FINAL_BIN="${FINAL_TARGET}/release/quicfuscate"
[[ -x "$FINAL_BIN" ]] || die "final binary missing at ${FINAL_BIN}"
cp -p "$FINAL_BIN" "$ARTIFACT"

python3 - "$RUN_DIR" "$ARTIFACT" "$MERGED" "${#PROFS[@]}" "$SCENARIO" <<'PY'
import json, sys, pathlib
run, art, merged, nprofs, scen = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
m = {
    "schema": "quicfuscate.pgo-dataplane.v1",
    "scenario": scen,
    "profile_files": nprofs,
    "merged_profile": merged,
    "binary": art,
    "binary_bytes": pathlib.Path(art).stat().st_size,
}
pathlib.Path(run, "manifest.json").write_text(json.dumps(m, indent=1))
PY

echo
echo "=== PGO dataplane build complete ==="
echo "Binary:   ${ARTIFACT}"
echo "Manifest: ${RUN_DIR}/manifest.json"
