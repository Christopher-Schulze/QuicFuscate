#!/usr/bin/env bash
# Repeated exact-artifact high-loss acceptance for TODO-557.
#
# Runs the adversity loss contract three times in isolated artifact paths.
# Every child manifest remains raw evidence; summary.tsv is the machine-readable
# aggregate. A missing result, an incomplete matrix, a failed child, or any
# declared loss-bound violation fails the aggregate.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
LOSS_HARNESS="$SCRIPT_DIR/tun-e2e-fec-netem-adversity.sh"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-fec-loss-stability-$$}"
LOSS_TRIALS=3
LOSS_PING_COUNT=200
EXPECTED_SCENARIOS=(loss-0 loss-1 loss-5 loss-10 loss-25 loss-50)

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

validate_trial_manifest() {
    local trial="$1"
    local manifest="$2"
    local scenario result payload loss_property rtt_property maximum_property loss rtt_ms maximum
    local result_count=0
    local expected
    local -A seen=()

    [ -f "$manifest" ] || return 1
    grep -Fx "suite=loss" "$manifest" >/dev/null || return 1
    grep -Fx "binary_sha256=$(sha256sum "$BINARY" | awk '{print $1}')" "$manifest" >/dev/null || return 1
    grep -Fx "ping_count=$LOSS_PING_COUNT" "$manifest" >/dev/null || return 1
    grep -Fx "runtime_failure_count=0" "$manifest" >/dev/null || return 1

    while IFS= read -r result; do
        payload="${result#result=}"
        scenario="${payload%%:*}"
        payload="${payload#*:}"
        IFS=',' read -r loss_property rtt_property maximum_property <<< "$payload"
        loss="${loss_property#tunnel_loss=}"
        rtt_ms="${rtt_property#rtt_ms=}"
        maximum="${maximum_property#maximum_loss=}"
        [[ "$loss" =~ ^[0-9]+$ && "$rtt_ms" =~ ^[0-9]+([.][0-9]+)?$ && "$maximum" =~ ^[0-9]+$ ]] || return 1
        [ -z "${seen[$scenario]:-}" ] || return 1
        seen["$scenario"]=1
        (( loss <= maximum )) || return 1
        printf '%s\t%s\t%s\t%s\t%s\n' "$trial" "$scenario" "$loss" "$rtt_ms" "$maximum" \
            >> "$ARTIFACT_DIR/summary.tsv"
        result_count=$((result_count + 1))
    done < <(grep '^result=loss-' "$manifest")

    [ "$result_count" -eq "${#EXPECTED_SCENARIOS[@]}" ] || return 1
    for expected in "${EXPECTED_SCENARIOS[@]}"; do
        [ "${seen[$expected]:-}" = "1" ] || return 1
    done
}

main() {
    [ "$(id -u)" -eq 0 ] || fail "this harness requires root"
    require_command bash
    require_command grep
    require_command sha256sum
    [ -x "$BINARY" ] || fail "release artifact is not executable: $BINARY"
    [ -x "$LOSS_HARNESS" ] || fail "loss harness is not executable: $LOSS_HARNESS"
    validate_artifact_directory

    mkdir "$ARTIFACT_DIR" || fail "could not create artifact directory: $ARTIFACT_DIR"
    printf 'trial\tscenario\ttunnel_loss_percent\trtt_ms\tmaximum_loss_percent\n' \
        > "$ARTIFACT_DIR/summary.tsv"
    printf 'binary_sha256=%s\n' "$(sha256sum "$BINARY" | awk '{print $1}')" \
        > "$ARTIFACT_DIR/run-manifest.txt"
    printf 'loss_trials=%s\n' "$LOSS_TRIALS" >> "$ARTIFACT_DIR/run-manifest.txt"
    printf 'loss_ping_count=%s\n' "$LOSS_PING_COUNT" >> "$ARTIFACT_DIR/run-manifest.txt"

    local trial trial_dir manifest child_status manifest_status trial_failed failures=0
    for ((trial = 1; trial <= LOSS_TRIALS; trial++)); do
        trial_dir="$ARTIFACT_DIR/trial-${trial}"
        printf 'Trial %s/%s\n' "$trial" "$LOSS_TRIALS"
        trial_failed=0
        if env QF_ADVERSITY_SUITE=loss QF_ADVERSITY_PING_COUNT="$LOSS_PING_COUNT" \
            QF_E2E_ARTIFACT_DIR="$trial_dir" QF_E2E_BINARY="$BINARY" "$LOSS_HARNESS"; then
            child_status=0
        else
            child_status=1
            trial_failed=1
        fi
        manifest="$trial_dir/run-manifest.txt"
        if validate_trial_manifest "$trial" "$manifest"; then
            manifest_status=0
        else
            manifest_status=1
            trial_failed=1
            printf 'FAIL: trial %s has missing, duplicate, incomplete, or out-of-contract results\n' "$trial" >&2
        fi
        failures=$((failures + trial_failed))
        printf 'trial_status=%s:child=%s:manifest=%s\n' \
            "$trial" "$child_status" "$manifest_status" >> "$ARTIFACT_DIR/run-manifest.txt"
    done

    [ "$failures" -eq 0 ] || fail "loss stability aggregate has ${failures} failure(s): $ARTIFACT_DIR"
    printf 'PASS: %s isolated loss trials retained in %s\n' "$LOSS_TRIALS" "$ARTIFACT_DIR"
}

main "$@"
