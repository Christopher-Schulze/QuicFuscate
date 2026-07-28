#!/usr/bin/env bash
# Repeated exact-artifact dual-stack throughput acceptance for TODO-559.
#
# Runs the complete three-client gate three times with per-trial external egress
# evidence. Every child artifact remains raw evidence. The aggregate refuses a
# mixed binary, missing receiver evidence, incomplete egress summaries, a PMTU
# gain below the existing gate, or an invalid black-hole recovery result.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DUAL_STACK_HARNESS="$SCRIPT_DIR/tun-e2e-multi-client-dual-stack-netns.sh"
AGGREGATOR="$SCRIPT_DIR/utils/aggregate-dual-stack-stability.py"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-dual-stack-stability-$$}"
STABILITY_TRIALS=3

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

validate_artifact_directory() {
    [ "${ARTIFACT_DIR#/}" != "$ARTIFACT_DIR" ] \
        || fail "QF_E2E_ARTIFACT_DIR must be an absolute path"
    [ ! -e "$ARTIFACT_DIR" ] \
        || fail "refusing to overwrite existing artifact path: $ARTIFACT_DIR"
    [ -d "$(dirname "$ARTIFACT_DIR")" ] \
        || fail "artifact parent directory does not exist: $(dirname "$ARTIFACT_DIR")"
}

append_trial_evidence() {
    local trial="$1"
    local trial_dir="$2"
    local binary_hash="$3"

    python3 "$AGGREGATOR" \
        --trial "$trial" \
        --artifact-dir "$trial_dir" \
        --binary-sha256 "$binary_hash" \
        --summary "$ARTIFACT_DIR/summary.tsv"
}

main() {
    [ "$(id -u)" -eq 0 ] || fail "this harness requires root"
    require_command bash
    require_command dirname
    require_command python3
    require_command sha256sum
    [ -x "$BINARY" ] || fail "release artifact is not executable: $BINARY"
    [ -x "$DUAL_STACK_HARNESS" ] || fail "dual-stack harness is not executable: $DUAL_STACK_HARNESS"
    [ -r "$AGGREGATOR" ] || fail "stability aggregator is unreadable: $AGGREGATOR"
    validate_artifact_directory

    local binary_hash
    binary_hash="$(sha256sum "$BINARY" | awk '{print $1}')"
    mkdir "$ARTIFACT_DIR" || fail "could not create artifact directory: $ARTIFACT_DIR"
    printf 'trial\tbinary_sha256\tdefault_bps\topt_in_bps\tgain_percent\tblack_hole_detection_seconds\tblack_hole_receiver_bytes\tblack_hole_elapsed_seconds\tdefault_trial_1_max_gap_us\tdefault_trial_2_max_gap_us\tdefault_trial_3_max_gap_us\topt_in_trial_1_max_gap_us\topt_in_trial_2_max_gap_us\topt_in_trial_3_max_gap_us\n' \
        > "$ARTIFACT_DIR/summary.tsv"
    printf 'binary_sha256=%s\n' "$binary_hash" > "$ARTIFACT_DIR/run-manifest.txt"
    printf 'stability_trials=%s\n' "$STABILITY_TRIALS" >> "$ARTIFACT_DIR/run-manifest.txt"
    printf 'external_egress_capture=1\n' >> "$ARTIFACT_DIR/run-manifest.txt"

    local trial trial_dir child_status failures=0
    for ((trial = 1; trial <= STABILITY_TRIALS; trial++)); do
        trial_dir="$ARTIFACT_DIR/trial-${trial}"
        printf 'Trial %s/%s\n' "$trial" "$STABILITY_TRIALS"
        if env QF_E2E_EXTERNAL_EGRESS_CAPTURE=1 QF_E2E_ARTIFACT_DIR="$trial_dir" QF_E2E_BINARY="$BINARY" \
            "$DUAL_STACK_HARNESS"; then
            child_status=0
        else
            child_status=1
            failures=$((failures + 1))
        fi
        if ! append_trial_evidence "$trial" "$trial_dir" "$binary_hash"; then
            printf 'FAIL: trial %s has missing, inconsistent, or out-of-contract evidence\n' "$trial" >&2
            failures=$((failures + 1))
        fi
        printf 'trial_status=%s:%s\n' "$trial" "$child_status" >> "$ARTIFACT_DIR/run-manifest.txt"
    done

    [ "$failures" -eq 0 ] || fail "dual-stack stability aggregate has ${failures} failure(s): $ARTIFACT_DIR"
    printf 'PASS: %s isolated dual-stack trials retained in %s\n' "$STABILITY_TRIALS" "$ARTIFACT_DIR"
}

main "$@"
