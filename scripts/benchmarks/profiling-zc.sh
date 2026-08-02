#!/usr/bin/env bash
# io_uring SendMsgZc zero-copy profiling.
#
# This runner proves the opt-in SendMsgZc path through the product binary's
# telemetry endpoint. It records no pass result unless both SendMsgZc send and
# notification counters are positive.
#
# Requirements:
#   - Linux kernel 6.0 or newer
#   - Release binary with the io_uring transport available
#   - Root access for perf record
#   - FlameGraph's flamegraph.pl and stackcollapse-perf.pl
#
# Usage:
#   sudo ./profiling-zc.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/scripts/tests/lib/lib-common.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/profiling-common.sh"

PROJECT_ROOT="$REPO_ROOT"
BINARY_OVERRIDE=""
OUTPUT_ROOT_OVERRIDE=""
FLAMEGRAPH_DIR="/tmp/FlameGraph"
CERT_OVERRIDE=""
KEY_OVERRIDE=""
DURATION=30
READY_TIMEOUT=15
DRY_RUN=0
SCENARIO_FILTER=""

usage() {
    cat <<'EOF'
Usage: profiling-zc.sh [options]

Runs the real product zero-copy path with telemetry and fail-closed evidence.
Native Linux, kernel, privilege, and profiling prerequisites are recorded as
UNAVAILABLE when this host cannot provide them.

Options:
  --project-root PATH       Checkout containing the release binary
  --binary PATH             quicfuscate binary override
  --output-dir PATH         Profiling output root
  --flamegraph-dir PATH     Directory containing flamegraph.pl and stackcollapse-perf.pl
  --cert PATH               Server certificate override
  --key PATH                Server key override
  --duration SECONDS        Profile duration (1..3600)
  --ready-timeout SECONDS  Process/log readiness timeout (1..120)
  --scenario zc             Run the SendMsgZc telemetry scenario
  --dry-run                 Record the planned scenario without executing commands
  --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-root|--binary|--output-dir|--flamegraph-dir|--cert|--key|--duration|--ready-timeout|--scenario)
            [[ $# -ge 2 ]] || { error "Missing value for $1"; exit 2; }
            case "$1" in
                --project-root) PROJECT_ROOT="$2";;
                --binary) BINARY_OVERRIDE="$2";;
                --output-dir) OUTPUT_ROOT_OVERRIDE="$2";;
                --flamegraph-dir) FLAMEGRAPH_DIR="$2";;
                --cert) CERT_OVERRIDE="$2";;
                --key) KEY_OVERRIDE="$2";;
                --duration) DURATION="$2";;
                --ready-timeout) READY_TIMEOUT="$2";;
                --scenario) SCENARIO_FILTER="$2";;
            esac
            shift 2
            ;;
        --dry-run) DRY_RUN=1; shift;;
        --help|-h) usage; exit 0;;
        *) error "Unknown argument: $1"; usage >&2; exit 2;;
    esac
done

BINARY="${BINARY_OVERRIDE:-$PROJECT_ROOT/target/release/quicfuscate}"
OUTPUT_DIR="${OUTPUT_ROOT_OVERRIDE:-$PROJECT_ROOT/docs/profiling}"
CERT="${CERT_OVERRIDE:-$PROJECT_ROOT/config/local/server.crt}"
KEY="${KEY_OVERRIDE:-$PROJECT_ROOT/config/local/server.key}"
FLAMEGRAPH_PL="$FLAMEGRAPH_DIR/flamegraph.pl"
STACKCOLLAPSE="$FLAMEGRAPH_DIR/stackcollapse-perf.pl"

validate_positive_int "duration" "$DURATION" 3600
validate_positive_int "ready timeout" "$READY_TIMEOUT" 120
validate_control_free_value "project root" "$PROJECT_ROOT" 4096
validate_control_free_value "binary path" "$BINARY" 4096
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
validate_control_free_value "flamegraph directory" "$FLAMEGRAPH_DIR" 4096
validate_control_free_value "certificate path" "$CERT" 4096
validate_control_free_value "key path" "$KEY" 4096

if [[ -n "$SCENARIO_FILTER" && "$SCENARIO_FILTER" != zc ]]; then
    error "unknown scenario label: $SCENARIO_FILTER"
    exit 2
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTPUT_DIR"
RUN_DIR="$OUTPUT_DIR/zc-${TIMESTAMP}-$$"
mkdir "$RUN_DIR"
MANIFEST="$RUN_DIR/manifest.json"

SOURCE_REVISION="$(profile_git_revision "$PROJECT_ROOT")"
EXECUTABLE_SHA256="missing"
[[ -f "$BINARY" ]] && EXECUTABLE_SHA256="$(profile_sha256_file "$BINARY")"
HOST_NAME="$(hostname 2>/dev/null || printf '%s' unknown)"
KERNEL="$(uname -srmo 2>/dev/null || uname -s)"
PYTHON_PATH="$(profile_command_path python3)"
PERF_PATH="$(profile_command_path perf)"
CURL_PATH="$(profile_command_path curl)"
TOOL_VERSIONS_JSON="$(profile_tool_versions_json \
    "python3=$PYTHON_PATH" "perf=$PERF_PATH" "curl=$CURL_PATH" \
    "flamegraph=$FLAMEGRAPH_PL" "stackcollapse=$STACKCOLLAPSE")"

KERNEL_MAJOR="$(uname -r | awk -F. '{print $1}')"
PREFLIGHT_REASONS=()
if (( ! DRY_RUN )); then
    [[ -x "$BINARY" ]] || PREFLIGHT_REASONS+=("missing_binary")
    [[ -f "$CERT" ]] || PREFLIGHT_REASONS+=("missing_certificate")
    [[ -f "$KEY" ]] || PREFLIGHT_REASONS+=("missing_key")
    [[ -n "$PYTHON_PATH" ]] || PREFLIGHT_REASONS+=("missing_python3")
    [[ -n "$PERF_PATH" ]] || PREFLIGHT_REASONS+=("missing_perf")
    [[ -n "$CURL_PATH" ]] || PREFLIGHT_REASONS+=("missing_curl")
    [[ -x "$FLAMEGRAPH_PL" ]] || PREFLIGHT_REASONS+=("missing_flamegraph")
    [[ -x "$STACKCOLLAPSE" ]] || PREFLIGHT_REASONS+=("missing_stackcollapse")
    [[ "$KERNEL_MAJOR" =~ ^[0-9]+$ && "$KERNEL_MAJOR" -ge 6 ]] || PREFLIGHT_REASONS+=("kernel_sendmsg_zc_unavailable")
    [[ "$(uname -s)" == Linux ]] || PREFLIGHT_REASONS+=("requires_linux")
    [[ "$(id -u)" -eq 0 ]] || PREFLIGHT_REASONS+=("requires_root")
fi
PREFLIGHT_STATUS="PASS"
PREFLIGHT_REASON=""
if (( DRY_RUN )); then
    PREFLIGHT_STATUS="SKIP"
    PREFLIGHT_REASON="dry_run"
elif (( ${#PREFLIGHT_REASONS[@]} > 0 )); then
    PREFLIGHT_STATUS="UNAVAILABLE"
    PREFLIGHT_REASON="$(IFS=,; printf '%s' "${PREFLIGHT_REASONS[*]}")"
fi
PREREQUISITES_JSON="$(profile_pairs_json \
    mode="$([[ "$DRY_RUN" -eq 1 ]] && printf '%s' dry_run || printf '%s' live)" \
    binary="$([[ -x "$BINARY" ]] && printf '%s' present || printf '%s' missing)" \
    certificate="$([[ -f "$CERT" ]] && printf '%s' present || printf '%s' missing)" \
    key="$([[ -f "$KEY" ]] && printf '%s' present || printf '%s' missing)" \
    perf="$([[ -n "$PERF_PATH" ]] && printf '%s' present || printf '%s' missing)" \
    curl="$([[ -n "$CURL_PATH" ]] && printf '%s' present || printf '%s' missing)" \
    flamegraph="$([[ -x "$FLAMEGRAPH_PL" ]] && printf '%s' present || printf '%s' missing)" \
    stackcollapse="$([[ -x "$STACKCOLLAPSE" ]] && printf '%s' present || printf '%s' missing)" \
    kernel="$KERNEL" kernel_major="$KERNEL_MAJOR" zc_opt_in=QUICFUSCATE_IO_URING_ZC=1 \
    status="$PREFLIGHT_STATUS" reason="$PREFLIGHT_REASON")"

SCENARIO_FILES=()
FAILURES=0
UNAVAILABLE_COUNT=0

write_csv_row() {
    local file="$1"; shift
    local first=1
    local field
    for field in "$@"; do
        (( first )) || printf ',' >> "$file"
        first=0
        profile_csv_field "$field" >> "$file"
    done
    printf '\n' >> "$file"
}

record_scenario() {
    local label="$1"; local title="$2"; shift 2
    local result="$1"; local reason="$2"; local command="$3"; shift 3
    case "$result" in
        FAIL) FAILURES=$((FAILURES + 1));;
        UNAVAILABLE) UNAVAILABLE_COUNT=$((UNAVAILABLE_COUNT + 1));;
    esac
    local file="$RUN_DIR/scenario-${label}.json"
    profile_write_scenario "$file" zc "$label" "$title" "$result" "$reason" "$command" \
        "$SOURCE_REVISION" "$EXECUTABLE_SHA256" "$HOST_NAME" "$KERNEL" "$TOOL_VERSIONS_JSON" "$PREREQUISITES_JSON" "$@"
    SCENARIO_FILES+=("$file")
}

allocate_loopback_ports() {
    python3 - <<'PY'
import socket

sockets = []
try:
    ports = []
    for _ in range(3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
        ports.append(str(sock.getsockname()[1]))
    print(" ".join(ports))
finally:
    for sock in sockets:
        sock.close()
PY
}

run_zc_scenario() {
    local label="$1"; local title="$2"
    local csv="$RUN_DIR/scenario-${label}.csv"
    local server_log="$RUN_DIR/server-${label}.log"
    local client_log="$RUN_DIR/client-${label}.log"
    local server_metrics="$RUN_DIR/server-${label}-telemetry.txt"
    local client_metrics="$RUN_DIR/client-${label}-telemetry.txt"
    local server_metrics_error="$RUN_DIR/server-${label}-telemetry.error"
    local client_metrics_error="$RUN_DIR/client-${label}-telemetry.error"
    local perf_data="$RUN_DIR/perf-${label}.data"
    local perf_log="$RUN_DIR/perf-${label}.log"
    local flamegraph="$RUN_DIR/flamegraph-${label}.svg"
    local flamegraph_log="$RUN_DIR/flamegraph-${label}.log"
    local started_at; started_at="$(profile_now_utc)"
    local quic_port=4433; local server_metrics_port=19898; local client_metrics_port=19899
    local command_json=""
    local result="PASS"; local reason=""
    local readiness_status="SKIP"; local readiness_reason=""
    local metrics_status="SKIP"; local metrics_complete=false; local metrics_json="{}"
    local sends_total=""; local notifs_total=""
    local perf_status="SKIP"; local perf_exit_status="null"; local perf_data_retained=false
    local flamegraph_status="SKIP"; local flamegraph_exit_status="null"
    local cleanup_status="PASS"; local termination_requested=false
    local server_pid=""; local client_pid=""; local perf_pid=""
    local server_exit_status="null"; local client_exit_status="null"
    local server_command=(); local client_command=()

    printf 'scenario,label,result,reason,quic_port,server_metrics,client_metrics,sendmsg_zc_sends,sendmsg_zc_notifs,perf_status,flamegraph_status\n' > "$csv"

    if (( ! DRY_RUN )) && [[ "$PREFLIGHT_STATUS" == PASS ]]; then
        local port_line
        if ! port_line="$(allocate_loopback_ports)"; then
            result="FAIL"
            reason="port_allocation_failed"
        else
            read -r quic_port server_metrics_port client_metrics_port <<< "$port_line"
        fi
    fi

    server_command=(env "QUICFUSCATE_IO_URING_ZC=1" "QUICFUSCATE_METRICS_ADDR=127.0.0.1:${server_metrics_port}" \
        "$BINARY" --telemetry server --cert "$CERT" --key "$KEY" --listen "127.0.0.1:${quic_port}" --fec-mode auto -v)
    client_command=(env "QUICFUSCATE_IO_URING_ZC=1" "QUICFUSCATE_METRICS_ADDR=127.0.0.1:${client_metrics_port}" \
        "$BINARY" --telemetry client --remote "127.0.0.1:${quic_port}" --url https://127.0.0.1/ \
        --ca-file "$CERT" --verify-peer --disable-doh -v)
    command_json="$(profile_command_bundle_json \
        "server=$(profile_command_json "${server_command[@]}")" \
        "client=$(profile_command_json "${client_command[@]}")")"

    if (( DRY_RUN )); then
        record_scenario "$label" "$title" SKIP dry_run "$command_json" \
            "$(profile_typed_pairs_json status=SKIP method=server_log_and_client_log)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null server_exit_status=null client_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null retained=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=SKIP complete=bool:false sends_total=null notifs_total=null)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" SKIP dry_run "$quic_port" "" "" "" "" SKIP SKIP
        return
    fi
    if [[ "$PREFLIGHT_STATUS" != PASS ]]; then
        record_scenario "$label" "$title" UNAVAILABLE "$PREFLIGHT_REASON" "$command_json" \
            "$(profile_typed_pairs_json status=UNAVAILABLE method=preflight)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null server_exit_status=null client_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null data_file=null retained=bool:false)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE complete=bool:false sends_total=null notifs_total=null)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" UNAVAILABLE "$PREFLIGHT_REASON" "$quic_port" "" "" "" "" UNAVAILABLE UNAVAILABLE
        return
    fi
    if [[ "$result" != PASS ]]; then
        record_scenario "$label" "$title" FAIL "$reason" "$command_json" \
            "$(profile_typed_pairs_json status=FAIL method=port_allocation)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null server_exit_status=null client_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null retained=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=FAIL complete=bool:false sends_total=null notifs_total=null)" \
            "$(profile_typed_pairs_json status=PASS perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" FAIL "$reason" "$quic_port" "" "" "" "" SKIP SKIP
        return
    fi

    echo "=== Scenario $label: $title ==="
    "${server_command[@]}" >"$server_log" 2>&1 &
    server_pid=$!
    if profile_wait_for_pid_alive "$server_pid" "$READY_TIMEOUT" && \
        profile_wait_for_log_pattern "$server_log" "Server listening on" "$READY_TIMEOUT"; then
        readiness_status="PASS"
    else
        readiness_status="FAIL"
        readiness_reason="server_not_ready"
        result="FAIL"
        reason="$readiness_reason"
    fi

    if [[ "$result" == PASS ]]; then
        "${client_command[@]}" >"$client_log" 2>&1 &
        client_pid=$!
        if profile_wait_for_pid_alive "$client_pid" "$READY_TIMEOUT" && \
            profile_wait_for_log_pattern "$client_log" "QUIC connection established" "$READY_TIMEOUT"; then
            readiness_status="PASS"
        else
            readiness_status="FAIL"
            readiness_reason="client_not_ready"
            result="FAIL"
            reason="$readiness_reason"
        fi
    fi

    if [[ "$result" == PASS ]]; then
        "$PERF_PATH" record -F 99 -g -p "$server_pid" -o "$perf_data" -- sleep "$DURATION" >"$perf_log" 2>&1 &
        perf_pid=$!
        profile_wait_status "$perf_pid"
        perf_exit_status="$PROFILE_LAST_WAIT_STATUS"
        if [[ "$perf_exit_status" == 0 && -s "$perf_data" ]]; then
            perf_status="PASS"
            perf_data_retained=true
        else
            perf_status="FAIL"
            result="FAIL"
            reason="perf_capture_failed"
        fi
    else
        metrics_status="FAIL"
    fi

    if [[ -n "$server_pid" && -n "$client_pid" ]]; then
        if "$CURL_PATH" -fsS --max-time "$READY_TIMEOUT" "http://127.0.0.1:${server_metrics_port}/telemetry" >"$server_metrics" 2>"$server_metrics_error" && \
            "$CURL_PATH" -fsS --max-time "$READY_TIMEOUT" "http://127.0.0.1:${client_metrics_port}/telemetry" >"$client_metrics" 2>"$client_metrics_error"; then
            if metrics_json="$(profile_telemetry_zc_json "$server_metrics" "$client_metrics" 2>"$RUN_DIR/metrics-${label}.log")"; then
                metrics_status="PASS"
                metrics_complete=true
                sends_total="$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["sends_total"])' "$metrics_json")"
                notifs_total="$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["notifs_total"])' "$metrics_json")"
            else
                metrics_status="FAIL"
                result="FAIL"
                [[ -n "$reason" ]] || reason="zc_telemetry_missing"
            fi
        else
            metrics_status="FAIL"
            result="FAIL"
            [[ -n "$reason" ]] || reason="telemetry_endpoint_unavailable"
        fi
    fi

    if [[ -n "$client_pid" ]]; then
        if profile_pid_alive "$client_pid"; then termination_requested=true; fi
        if ! profile_stop_pid "$client_pid"; then cleanup_status="FAIL"; fi
        client_exit_status="$PROFILE_LAST_WAIT_STATUS"
    fi
    if [[ -n "$server_pid" ]]; then
        if profile_pid_alive "$server_pid"; then termination_requested=true; fi
        if ! profile_stop_pid "$server_pid"; then cleanup_status="FAIL"; fi
        server_exit_status="$PROFILE_LAST_WAIT_STATUS"
    fi
    if [[ "$cleanup_status" != PASS ]]; then
        result="FAIL"
        [[ -n "$reason" ]] || reason="cleanup_failed"
    fi

    if [[ "$perf_status" == PASS ]]; then
        if profile_generate_flamegraph "$PERF_PATH" "$STACKCOLLAPSE" "$FLAMEGRAPH_PL" \
            "$perf_data" "$flamegraph" "$title" "$flamegraph_log"; then
            flamegraph_status="PASS"
            flamegraph_exit_status=0
        else
            flamegraph_status="FAIL"
            flamegraph_exit_status=1
            result="FAIL"
            [[ -n "$reason" ]] || reason="flamegraph_generation_failed"
        fi
    else
        flamegraph_status="UNAVAILABLE"
    fi

    record_scenario "$label" "$title" "$result" "${reason:-completed}" "$command_json" \
        "$(profile_typed_pairs_json status="$readiness_status" reason="$readiness_reason" server_log="$server_log" client_log="$client_log" server_metrics="http://127.0.0.1:${server_metrics_port}/telemetry" client_metrics="http://127.0.0.1:${client_metrics_port}/telemetry")" \
        "$(profile_typed_pairs_json server_pid="${server_pid:-null}" client_pid="${client_pid:-null}" server_exit_status="${server_exit_status:-null}" client_exit_status="${client_exit_status:-null}" termination_requested="bool:$termination_requested")" \
        "$(profile_typed_pairs_json status="$perf_status" exit_status="$perf_exit_status" data_file="$perf_data" retained="bool:$perf_data_retained")" \
        "$(profile_typed_pairs_json status="$flamegraph_status" exit_status="$flamegraph_exit_status" output_file="$flamegraph")" \
        "$(profile_typed_pairs_json status="$metrics_status" complete="bool:$metrics_complete" sends_total="${sends_total:-null}" notifs_total="${notifs_total:-null}" server_telemetry_file="$server_metrics" client_telemetry_file="$client_metrics")" \
        "$(profile_typed_pairs_json status="$cleanup_status" perf_data_retained="bool:$perf_data_retained")" \
        "$started_at" "$(profile_now_utc)"
    write_csv_row "$csv" "$label" "$label" "$result" "${reason:-completed}" "$quic_port" "127.0.0.1:${server_metrics_port}" "127.0.0.1:${client_metrics_port}" "${sends_total:-}" "${notifs_total:-}" "$perf_status" "$flamegraph_status"
}

run_zc_scenario zc "io_uring SendMsgZc telemetry proof"
profile_write_manifest "$MANIFEST" zc "$OUTPUT_DIR" "$SOURCE_REVISION" "$EXECUTABLE_SHA256" \
    "$HOST_NAME" "$KERNEL" "$TOOL_VERSIONS_JSON" "$PREREQUISITES_JSON" "$(profile_now_utc)" \
    "${SCENARIO_FILES[@]}"
echo "Profiling manifest: $MANIFEST"

if (( DRY_RUN )); then
    exit 0
fi
if (( FAILURES > 0 )); then
    exit 1
fi
if (( UNAVAILABLE_COUNT > 0 )); then
    exit 2
fi
exit 0
