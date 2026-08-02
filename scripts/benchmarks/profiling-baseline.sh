#!/usr/bin/env bash
# Description: Fail-closed loopback profiling baseline with durable scenario evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/scripts/tests/lib/lib-common.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/profiling-common.sh"

PROJECT_ROOT="$REPO_ROOT"
BINARY_OVERRIDE=""
HARNESS_OVERRIDE=""
OUTPUT_ROOT_OVERRIDE=""
FLAMEGRAPH_DIR="/tmp/FlameGraph"
CERT_OVERRIDE=""
KEY_OVERRIDE=""
DURATION=30
READY_TIMEOUT=10
DRY_RUN=0
SCENARIO_FILTER=""

usage() {
    cat <<'EOF'
Usage: profiling-baseline.sh [options]

Runs loopback UDP and QUIC profiling scenarios. Every run writes a unique
directory containing scenario JSON, CSV, logs, and a manifest.json.

Options:
  --project-root PATH       Checkout containing the release binaries
  --binary PATH             quicfuscate binary override
  --harness PATH            harness binary override
  --output-dir PATH         Profiling output root
  --flamegraph-dir PATH     Directory containing flamegraph.pl and stackcollapse-perf.pl
  --cert PATH               Server certificate override
  --key PATH                Server key override
  --duration SECONDS        Profile duration per scenario (1..3600)
  --ready-timeout SECONDS  Process/log readiness timeout (1..120)
  --scenario LABEL          Run one scenario a-f
  --dry-run                 Record planned scenarios without executing commands
  --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-root|--binary|--harness|--output-dir|--flamegraph-dir|--cert|--key|--duration|--ready-timeout|--scenario)
            [[ $# -ge 2 ]] || { error "Missing value for $1"; exit 2; }
            case "$1" in
                --project-root) PROJECT_ROOT="$2";;
                --binary) BINARY_OVERRIDE="$2";;
                --harness) HARNESS_OVERRIDE="$2";;
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
HARNESS="${HARNESS_OVERRIDE:-$PROJECT_ROOT/target/release/harness}"
OUTPUT_DIR="${OUTPUT_ROOT_OVERRIDE:-$PROJECT_ROOT/docs/profiling}"
CERT="${CERT_OVERRIDE:-$PROJECT_ROOT/config/local/server.crt}"
KEY="${KEY_OVERRIDE:-$PROJECT_ROOT/config/local/server.key}"
FLAMEGRAPH_PL="$FLAMEGRAPH_DIR/flamegraph.pl"
STACKCOLLAPSE="$FLAMEGRAPH_DIR/stackcollapse-perf.pl"

validate_positive_int "duration" "$DURATION" 3600
validate_positive_int "ready timeout" "$READY_TIMEOUT" 120
validate_control_free_value "project root" "$PROJECT_ROOT" 4096
validate_control_free_value "binary path" "$BINARY" 4096
validate_control_free_value "harness path" "$HARNESS" 4096
validate_control_free_value "output directory" "$OUTPUT_DIR" 4096
validate_control_free_value "flamegraph directory" "$FLAMEGRAPH_DIR" 4096
validate_control_free_value "certificate path" "$CERT" 4096
validate_control_free_value "key path" "$KEY" 4096

SCENARIO_LABELS=(a b c d e f)
if [[ -n "$SCENARIO_FILTER" ]] && case " ${SCENARIO_LABELS[*]} " in *" $SCENARIO_FILTER "*) false;; *) true;; esac; then
    error "unknown scenario label: $SCENARIO_FILTER"
    exit 2
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTPUT_DIR"
RUN_DIR="$OUTPUT_DIR/baseline-${TIMESTAMP}-$$"
mkdir "$RUN_DIR"
MANIFEST="$RUN_DIR/manifest.json"

SOURCE_REVISION="$(profile_git_revision "$PROJECT_ROOT")"
EXECUTABLE_SHA256="missing"
[[ -f "$BINARY" ]] && EXECUTABLE_SHA256="$(profile_sha256_file "$BINARY")"
HOST_NAME="$(hostname 2>/dev/null || printf '%s' unknown)"
KERNEL="$(uname -srmo 2>/dev/null || uname -s)"
PERF_PATH="$(profile_command_path perf)"
PYTHON_PATH="$(profile_command_path python3)"
TOOL_VERSIONS_JSON="$(profile_tool_versions_json \
    "python3=$PYTHON_PATH" "perf=$PERF_PATH" \
    "flamegraph=$FLAMEGRAPH_PL" "stackcollapse=$STACKCOLLAPSE")"

PREFLIGHT_REASONS=()
if (( ! DRY_RUN )); then
    [[ -x "$BINARY" ]] || PREFLIGHT_REASONS+=("missing_binary")
    [[ -x "$HARNESS" ]] || PREFLIGHT_REASONS+=("missing_harness")
    [[ -f "$CERT" ]] || PREFLIGHT_REASONS+=("missing_certificate")
    [[ -f "$KEY" ]] || PREFLIGHT_REASONS+=("missing_key")
    [[ -n "$PYTHON_PATH" ]] || PREFLIGHT_REASONS+=("missing_python3")
    [[ -n "$PERF_PATH" ]] || PREFLIGHT_REASONS+=("missing_perf")
    [[ -x "$FLAMEGRAPH_PL" ]] || PREFLIGHT_REASONS+=("missing_flamegraph")
    [[ -x "$STACKCOLLAPSE" ]] || PREFLIGHT_REASONS+=("missing_stackcollapse")
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
    harness="$([[ -x "$HARNESS" ]] && printf '%s' present || printf '%s' missing)" \
    certificate="$([[ -f "$CERT" ]] && printf '%s' present || printf '%s' missing)" \
    key="$([[ -f "$KEY" ]] && printf '%s' present || printf '%s' missing)" \
    perf="$([[ -n "$PERF_PATH" ]] && printf '%s' present || printf '%s' missing)" \
    flamegraph="$([[ -x "$FLAMEGRAPH_PL" ]] && printf '%s' present || printf '%s' missing)" \
    stackcollapse="$([[ -x "$STACKCOLLAPSE" ]] && printf '%s' present || printf '%s' missing)" \
    status="$PREFLIGHT_STATUS" reason="$PREFLIGHT_REASON")"

SCENARIO_FILES=()

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

FAILURES=0
UNAVAILABLE_COUNT=0

record_scenario() {
    local label="$1"
    local title="$2"
    shift 2
    local result="$1"
    local reason="$2"
    local command="$3"
    shift 3
    case "$result" in
        FAIL) FAILURES=$((FAILURES + 1));;
        UNAVAILABLE) UNAVAILABLE_COUNT=$((UNAVAILABLE_COUNT + 1));;
    esac
    local file="$RUN_DIR/scenario-${label}.json"
    profile_write_scenario "$file" baseline "$label" "$title" "$result" "$reason" "$command" \
        "$SOURCE_REVISION" "$EXECUTABLE_SHA256" "$HOST_NAME" "$KERNEL" "$TOOL_VERSIONS_JSON" "$PREREQUISITES_JSON" "$@"
    SCENARIO_FILES+=("$file")
}

run_harness_scenario() {
    local label="$1"
    local title="$2"
    local size="$3"
    local batch="$4"
    local iters="$5"
    local csv="$RUN_DIR/scenario-${label}.csv"
    local log_file="$RUN_DIR/harness-${label}.log"
    local perf_data="$RUN_DIR/perf-${label}.data"
    local perf_log="$RUN_DIR/perf-${label}.log"
    local flamegraph="$RUN_DIR/flamegraph-${label}.svg"
    local flamegraph_log="$RUN_DIR/flamegraph-${label}.log"
    local started_at; started_at="$(profile_now_utc)"
    local command=("$HARNESS" udp-throughput --size "$size" --iters "$iters" --batch "$batch")
    local command_text; command_text="$(profile_shell_command "${command[@]}")"
    local result="PASS"; local reason=""
    local readiness_status="NOT_STARTED"; local metric_line=""
    local process_status="null"; local termination_requested=false
    local perf_status="SKIP"; local perf_exit="null"
    local perf_pid=""
    local flamegraph_status="SKIP"; local flamegraph_exit="null"
    local metrics_status="SKIP"; local metrics_complete=false
    local cleanup_status="PASS"; local perf_data_retained=false

    printf 'scenario,label,size,batch,iters,result,reason,process_exit,perf_status,flamegraph_status,metrics_status,metric\n' > "$csv"
    if (( DRY_RUN )); then
        record_scenario "$label" "$title" "SKIP" "dry_run" "$command_text" \
            "$(profile_pairs_json status=skipped method=none)" \
            "$(profile_typed_pairs_json pid=null exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=SKIP complete=bool:false value=)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$size" "$batch" "$iters" SKIP dry_run "" SKIP SKIP SKIP ""
        return
    fi
    if [[ "$PREFLIGHT_STATUS" != PASS ]]; then
        record_scenario "$label" "$title" "UNAVAILABLE" "$PREFLIGHT_REASON" "$command_text" \
            "$(profile_pairs_json status=not_checked method=preflight)" \
            "$(profile_typed_pairs_json pid=null exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE complete=bool:false value=)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$size" "$batch" "$iters" UNAVAILABLE "$PREFLIGHT_REASON" "" UNAVAILABLE UNAVAILABLE UNAVAILABLE ""
        return
    fi

    echo "=== Scenario $label: $title ==="
    echo "size=${size}B batch=$batch iters=$iters"
    "${command[@]}" >"$log_file" 2>&1 &
    local pid=$!
    if profile_wait_for_pid_alive "$pid" 2; then
        readiness_status="PASS"
    else
        readiness_status="FAIL"
        result="FAIL"
        reason="process_not_ready"
        process_status="$(profile_wait_status "$pid")"
    fi
    if [[ "$readiness_status" == PASS ]]; then
        local perf_command=("$PERF_PATH" record -F 99 -g -p "$pid" -o "$perf_data" -- sleep "$DURATION")
        "${perf_command[@]}" >"$perf_log" 2>&1 &
        perf_pid=$!
        if profile_wait_for_pid_exit "$pid" "$DURATION"; then
            profile_wait_status "$pid"
            process_status="$PROFILE_LAST_WAIT_STATUS"
            if profile_pid_alive "$perf_pid"; then
                if ! profile_stop_pid "$perf_pid"; then cleanup_status="FAIL"; fi
                perf_exit="$PROFILE_LAST_WAIT_STATUS"
            else
                profile_wait_status "$perf_pid"
                perf_exit="$PROFILE_LAST_WAIT_STATUS"
            fi
        else
            profile_wait_status "$perf_pid"
            perf_exit="$PROFILE_LAST_WAIT_STATUS"
            if profile_pid_alive "$pid"; then
                termination_requested=true
                if ! profile_stop_pid "$pid"; then cleanup_status="FAIL"; fi
                process_status="$PROFILE_LAST_WAIT_STATUS"
            else
                profile_wait_status "$pid"
                process_status="$PROFILE_LAST_WAIT_STATUS"
            fi
        fi
        if [[ "$perf_exit" == 0 || "$perf_exit" == 143 || "$perf_exit" == 15 ]] && [[ -s "$perf_data" ]]; then
            perf_status="PASS"
            perf_data_retained=true
        else
            perf_status="FAIL"
            result="FAIL"
            [[ -n "$reason" ]] || reason="perf_data_missing"
        fi
        if [[ "$perf_status" == PASS ]] && profile_generate_flamegraph "$PERF_PATH" "$STACKCOLLAPSE" "$FLAMEGRAPH_PL" "$perf_data" "$flamegraph" "$title" "$flamegraph_log"; then
            flamegraph_status="PASS"; flamegraph_exit=0
        else
            flamegraph_status="FAIL"; flamegraph_exit=1; result="FAIL"; [[ -n "$reason" ]] || reason="flamegraph_generation_failed"
        fi
        metric_line="$(tail -n 1 "$log_file")"
        if [[ "$metric_line" == *"variant=udpfast"* && "$metric_line" == *"sent_packets="* && "$metric_line" == *"recv_bytes="* && "$metric_line" == *"throughput_MiBps="* ]]; then
            metrics_status="PASS"; metrics_complete=true
        else
            metrics_status="FAIL"; result="FAIL"; [[ -n "$reason" ]] || reason="required_metrics_missing"
        fi
    fi
    [[ "$cleanup_status" == PASS ]] || { result="FAIL"; [[ -n "$reason" ]] || reason="cleanup_failed"; }
    local process_json; process_json="$(profile_typed_pairs_json pid="int:$pid" exit_status="int:$process_status" termination_requested="bool:$termination_requested")"
    local readiness_json; readiness_json="$(profile_pairs_json status="$readiness_status" method=process_liveness log_file="$log_file")"
    local perf_json; perf_json="$(profile_typed_pairs_json status="$perf_status" exit_status="$perf_exit" data_file="$perf_data" retained=bool:$perf_data_retained)"
    local flamegraph_json; flamegraph_json="$(profile_typed_pairs_json status="$flamegraph_status" exit_status="$flamegraph_exit" output_file="$flamegraph")"
    local metrics_json; metrics_json="$(profile_typed_pairs_json status="$metrics_status" complete=bool:$metrics_complete value="$metric_line")"
    local cleanup_json; cleanup_json="$(profile_typed_pairs_json status="$cleanup_status" perf_data_retained=bool:$perf_data_retained)"
    record_scenario "$label" "$title" "$result" "$reason" "$command_text" \
        "$readiness_json" "$process_json" "$perf_json" "$flamegraph_json" "$metrics_json" "$cleanup_json" \
        "$started_at" "$(profile_now_utc)"
    write_csv_row "$csv" "$label" "$label" "$size" "$batch" "$iters" "$result" "$reason" "$process_status" "$perf_status" "$flamegraph_status" "$metrics_status" "$metric_line"
}

run_connection_scenario() {
    local label="$1"; local title="$2"; local fec_mode="$3"; shift 3
    local -a mode_args=("$@")
    local server_log="$RUN_DIR/server-${label}.log"; local client_log="$RUN_DIR/client-${label}.log"
    local perf_data="$RUN_DIR/perf-${label}.data"; local perf_log="$RUN_DIR/perf-${label}.log"
    local flamegraph="$RUN_DIR/flamegraph-${label}-server.svg"; local flamegraph_log="$RUN_DIR/flamegraph-${label}-server.log"
    local csv="$RUN_DIR/scenario-${label}.csv"; local started_at; started_at="$(profile_now_utc)"
    local server_command=("$BINARY" server --cert "$CERT" --key "$KEY" --listen 127.0.0.1:4433 --fec-mode "$fec_mode" "${mode_args[@]}" -v)
    local client_command=("$BINARY" client --remote 127.0.0.1:4433 --fec-mode "$fec_mode" "${mode_args[@]}" -v)
    local command_text; command_text="server: $(profile_shell_command "${server_command[@]}"); client: $(profile_shell_command "${client_command[@]}")"
    local mode_args_text; mode_args_text="$(profile_shell_command "${mode_args[@]}")"
    local result="PASS"; local reason=""; local readiness_status="NOT_STARTED"; local process_status="null"
    local termination_requested=false; local perf_status="SKIP"; local perf_exit="null"; local flamegraph_status="SKIP"; local flamegraph_exit="null"
    local metrics_status="SKIP"; local metrics_complete=false; local rtt=""; local loss=""; local cleanup_status="PASS"; local perf_data_retained=false
    local server_exit_status="null"; local client_exit_status="null"; local rtt_line=""; local loss_line=""

    printf 'scenario,label,fec_mode,runtime_flags,result,reason,server_exit,client_exit,perf_status,flamegraph_status,metrics_status,rtt,loss\n' > "$csv"
    if (( DRY_RUN )); then
        record_scenario "$label" "$title" "SKIP" "dry_run" "$command_text" \
            "$(profile_pairs_json status=skipped method=process_and_log)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null server_exit_status=null client_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=SKIP complete=bool:false rtt= loss=)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$mode_args_text" SKIP dry_run "" "" SKIP SKIP SKIP "" ""
        return
    fi
    if [[ "$PREFLIGHT_STATUS" != PASS ]]; then
        record_scenario "$label" "$title" "UNAVAILABLE" "$PREFLIGHT_REASON" "$command_text" \
            "$(profile_pairs_json status=not_checked method=preflight)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null server_exit_status=null client_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE complete=bool:false rtt= loss=)" \
            "$(profile_typed_pairs_json status=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$mode_args_text" UNAVAILABLE "$PREFLIGHT_REASON" "" "" UNAVAILABLE UNAVAILABLE UNAVAILABLE "" ""
        return
    fi

    echo "=== Scenario $label: $title ==="
    "${server_command[@]}" >"$server_log" 2>&1 &
    local server_pid=$!
    local server_ready=false
    if profile_wait_for_pid_alive "$server_pid" 2 && profile_wait_for_log_pattern "$server_log" 'Server listening on' "$READY_TIMEOUT"; then
        server_ready=true
    fi
    if [[ "$server_ready" != true ]]; then
        result="FAIL"; reason="server_not_ready"; readiness_status="FAIL"
        if ! profile_stop_pid "$server_pid"; then cleanup_status="FAIL"; fi
        server_exit_status="$PROFILE_LAST_WAIT_STATUS"
        record_scenario "$label" "$title" "$result" "$reason" "$command_text" \
            "$(profile_pairs_json status=FAIL method=server_log_and_process)" \
            "$(profile_typed_pairs_json server_pid="int:$server_pid" client_pid=null server_exit_status="int:$server_exit_status" client_exit_status=null termination_requested=bool:true)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=FAIL complete=bool:false rtt= loss=)" \
            "$(profile_typed_pairs_json status="$cleanup_status" perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$mode_args_text" FAIL "$reason" "$server_exit_status" "" SKIP SKIP FAIL "" ""
        return
    fi

    "${client_command[@]}" >"$client_log" 2>&1 &
    local client_pid=$!
    local client_ready=false
    if profile_wait_for_pid_alive "$client_pid" 2 && profile_wait_for_log_pattern "$client_log" 'QUIC connection established' "$READY_TIMEOUT"; then
        client_ready=true
    fi
    if [[ "$client_ready" != true ]]; then
        result="FAIL"; reason="client_not_ready"; readiness_status="FAIL"
        if ! profile_stop_pid "$client_pid"; then cleanup_status="FAIL"; fi
        client_exit_status="$PROFILE_LAST_WAIT_STATUS"
        if ! profile_stop_pid "$server_pid"; then cleanup_status="FAIL"; fi
        server_exit_status="$PROFILE_LAST_WAIT_STATUS"
        record_scenario "$label" "$title" "$result" "$reason" "$command_text" \
            "$(profile_pairs_json status=FAIL method=server_and_client_log_and_process)" \
            "$(profile_typed_pairs_json server_pid="int:$server_pid" client_pid="int:$client_pid" server_exit_status="int:$server_exit_status" client_exit_status="int:$client_exit_status" termination_requested=bool:true)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=FAIL complete=bool:false rtt= loss=)" \
            "$(profile_typed_pairs_json status="$cleanup_status" perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$mode_args_text" FAIL "$reason" "$server_exit_status" "$client_exit_status" SKIP SKIP FAIL "" ""
        return
    fi

    local perf_command=("$PERF_PATH" record -F 99 -g -p "$server_pid" -o "$perf_data" -- sleep "$DURATION")
    if "${perf_command[@]}" >"$perf_log" 2>&1; then
        perf_status="PASS"; perf_exit=0
    else
        perf_status="FAIL"; perf_exit=$?; result="FAIL"; reason="perf_capture_failed"
    fi
    if rtt_line="$(grep -Eo 'RTT [0-9]+ ms' "$client_log" | tail -n 1)"; then
        rtt="$rtt_line"
    fi
    if loss_line="$(grep -Eo 'Loss [0-9.]+%' "$client_log" | tail -n 1)"; then
        loss="$loss_line"
    fi
    if [[ -n "$rtt" && -n "$loss" ]]; then
        metrics_status="PASS"; metrics_complete=true
    else
        metrics_status="FAIL"; result="FAIL"; [[ -n "$reason" ]] || reason="required_metrics_missing"
    fi
    if profile_pid_alive "$client_pid"; then termination_requested=true; fi
    if ! profile_stop_pid "$client_pid"; then cleanup_status="FAIL"; fi
    client_exit_status="$PROFILE_LAST_WAIT_STATUS"
    if profile_pid_alive "$server_pid"; then termination_requested=true; fi
    if ! profile_stop_pid "$server_pid"; then cleanup_status="FAIL"; fi
    server_exit_status="$PROFILE_LAST_WAIT_STATUS"
    if [[ "$perf_status" == PASS && -s "$perf_data" ]]; then
        perf_data_retained=true
    else
        perf_status="FAIL"; result="FAIL"; [[ -n "$reason" ]] || reason="perf_data_missing"
    fi
    if [[ "$perf_status" == PASS ]] && profile_generate_flamegraph "$PERF_PATH" "$STACKCOLLAPSE" "$FLAMEGRAPH_PL" "$perf_data" "$flamegraph" "$title (Server)" "$flamegraph_log"; then
        flamegraph_status="PASS"; flamegraph_exit=0
    else
        flamegraph_status="FAIL"; flamegraph_exit=1; result="FAIL"; [[ -n "$reason" ]] || reason="flamegraph_generation_failed"
    fi
    [[ "$cleanup_status" == PASS ]] || { result="FAIL"; [[ -n "$reason" ]] || reason="cleanup_failed"; }
    local process_json; process_json="$(profile_typed_pairs_json server_pid="int:$server_pid" client_pid="int:$client_pid" server_exit_status="int:$server_exit_status" client_exit_status="int:$client_exit_status" termination_requested="bool:$termination_requested")"
    local readiness_json; readiness_json="$(profile_pairs_json status=PASS method=server_and_client_log_and_process server_log="$server_log" client_log="$client_log")"
    local perf_json; perf_json="$(profile_typed_pairs_json status="$perf_status" exit_status="$perf_exit" data_file="$perf_data" retained=bool:$perf_data_retained)"
    local flamegraph_json; flamegraph_json="$(profile_typed_pairs_json status="$flamegraph_status" exit_status="$flamegraph_exit" output_file="$flamegraph")"
    local metrics_json; metrics_json="$(profile_typed_pairs_json status="$metrics_status" complete=bool:$metrics_complete rtt="$rtt" loss="$loss")"
    local cleanup_json; cleanup_json="$(profile_typed_pairs_json status="$cleanup_status" perf_data_retained=bool:$perf_data_retained)"
    record_scenario "$label" "$title" "$result" "$reason" "$command_text" "$readiness_json" "$process_json" "$perf_json" "$flamegraph_json" "$metrics_json" "$cleanup_json" "$started_at" "$(profile_now_utc)"
    write_csv_row "$csv" "$label" "$label" "$fec_mode" "$mode_args_text" "$result" "$reason" "$server_exit_status" "$client_exit_status" "$perf_status" "$flamegraph_status" "$metrics_status" "$rtt" "$loss"
}

echo "=== QuicFuscate Profiling Baseline ==="
echo "Project: $PROJECT_ROOT"
echo "Host: $HOST_NAME"
echo "Revision: $SOURCE_REVISION"
echo "Duration per scenario: ${DURATION}s"
echo "Run directory: $RUN_DIR"

if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == a ]]; then run_harness_scenario a "Pure UDP Throughput" 1200 32 50000; fi
if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == b ]]; then run_harness_scenario b "UDP Throughput Small Packets" 256 64 50000; fi
if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == c ]]; then run_harness_scenario c "UDP Throughput Large Batch" 1200 128 20000; fi
if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == d ]]; then run_connection_scenario d "QUIC connection (FEC off, cover features disabled)" off --disable-doh --disable-fronting --disable-http3; fi
if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == e ]]; then run_connection_scenario e "QUIC connection (FEC auto, default cover features)" auto; fi
if [[ -z "$SCENARIO_FILTER" || "$SCENARIO_FILTER" == f ]]; then run_connection_scenario f "QUIC connection (FEC auto, fronting and HTTP/3 cover disabled)" auto --disable-fronting --disable-http3; fi

profile_write_manifest "$MANIFEST" baseline "$OUTPUT_DIR" "$SOURCE_REVISION" "$EXECUTABLE_SHA256" "$HOST_NAME" "$KERNEL" "$TOOL_VERSIONS_JSON" "$PREREQUISITES_JSON" "$(profile_now_utc)" "${SCENARIO_FILES[@]}"
echo "Manifest: $MANIFEST"
echo "Scenarios: ${#SCENARIO_FILES[@]}  failures=$FAILURES  unavailable=$UNAVAILABLE_COUNT"

if (( DRY_RUN )); then
    exit 0
elif (( FAILURES > 0 )); then
    exit 1
elif (( UNAVAILABLE_COUNT > 0 )); then
    exit 2
fi
