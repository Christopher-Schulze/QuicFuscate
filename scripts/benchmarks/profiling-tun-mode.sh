#!/usr/bin/env bash
# TUN-mode profiling with fail-closed tc-netem, process, traffic, and evidence gates.
#
# Requirements:
#   - Root access
#   - Rust release build: cargo build --release --bin quicfuscate
#   - FlameGraph repo cloned to /tmp/FlameGraph
#   - iperf3 installed: apt install iperf3
#   - TUN module loaded: modprobe tun
#
# Usage:
#   sudo ./profiling-tun-mode.sh [options]

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
NETEM_INTERFACE="lo"

usage() {
    cat <<'EOF'
Usage: profiling-tun-mode.sh [options]

Runs real TUN data-plane scenarios under tc-netem. Native Linux/root
prerequisites are recorded as UNAVAILABLE when this host cannot provide them.

Options:
  --project-root PATH       Checkout containing the release binary
  --binary PATH             quicfuscate binary override
  --output-dir PATH         Profiling output root
  --flamegraph-dir PATH     Directory containing flamegraph.pl and stackcollapse-perf.pl
  --cert PATH               Server certificate override
  --key PATH                Server key override
  --duration SECONDS        Profile duration per scenario (1..3600)
  --ready-timeout SECONDS  Process/log readiness timeout (1..120)
  --netem-interface NAME    Interface passed to tc (default: lo)
  --scenario LABEL          Run one scenario g-k
  --dry-run                 Record planned scenarios without executing commands
  --help                    Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-root|--binary|--output-dir|--flamegraph-dir|--cert|--key|--duration|--ready-timeout|--netem-interface|--scenario)
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
                --netem-interface) NETEM_INTERFACE="$2";;
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
validate_control_free_value "netem interface" "$NETEM_INTERFACE" 128

SCENARIO_LABELS=(g h i j k)
if [[ -n "$SCENARIO_FILTER" ]] && case " ${SCENARIO_LABELS[*]} " in *" $SCENARIO_FILTER "*) false;; *) true;; esac; then
    error "unknown scenario label: $SCENARIO_FILTER"
    exit 2
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTPUT_DIR"
RUN_DIR="$OUTPUT_DIR/tun-${TIMESTAMP}-$$"
mkdir "$RUN_DIR"
MANIFEST="$RUN_DIR/manifest.json"

SOURCE_REVISION="$(profile_git_revision "$PROJECT_ROOT")"
EXECUTABLE_SHA256="missing"
[[ -f "$BINARY" ]] && EXECUTABLE_SHA256="$(profile_sha256_file "$BINARY")"
HOST_NAME="$(hostname 2>/dev/null || printf '%s' unknown)"
KERNEL="$(uname -srmo 2>/dev/null || uname -s)"
PYTHON_PATH="$(profile_command_path python3)"
PERF_PATH="$(profile_command_path perf)"
TC_PATH="$(profile_command_path tc)"
IPERF3_PATH="$(profile_command_path iperf3)"
TOOL_VERSIONS_JSON="$(profile_tool_versions_json \
    "python3=$PYTHON_PATH" "perf=$PERF_PATH" "tc=$TC_PATH" "iperf3=$IPERF3_PATH" \
    "flamegraph=$FLAMEGRAPH_PL" "stackcollapse=$STACKCOLLAPSE")"

PREFLIGHT_REASONS=()
if (( ! DRY_RUN )); then
    [[ -x "$BINARY" ]] || PREFLIGHT_REASONS+=("missing_binary")
    [[ -f "$CERT" ]] || PREFLIGHT_REASONS+=("missing_certificate")
    [[ -f "$KEY" ]] || PREFLIGHT_REASONS+=("missing_key")
    [[ -n "$PYTHON_PATH" ]] || PREFLIGHT_REASONS+=("missing_python3")
    [[ -n "$PERF_PATH" ]] || PREFLIGHT_REASONS+=("missing_perf")
    [[ -n "$TC_PATH" ]] || PREFLIGHT_REASONS+=("missing_tc")
    [[ -n "$IPERF3_PATH" ]] || PREFLIGHT_REASONS+=("missing_iperf3")
    [[ -x "$FLAMEGRAPH_PL" ]] || PREFLIGHT_REASONS+=("missing_flamegraph")
    [[ -x "$STACKCOLLAPSE" ]] || PREFLIGHT_REASONS+=("missing_stackcollapse")
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
    tc="$([[ -n "$TC_PATH" ]] && printf '%s' present || printf '%s' missing)" \
    iperf3="$([[ -n "$IPERF3_PATH" ]] && printf '%s' present || printf '%s' missing)" \
    root="$([[ "$(id -u)" -eq 0 ]] && printf '%s' yes || printf '%s' no)" \
    status="$PREFLIGHT_STATUS" reason="$PREFLIGHT_REASON")"

SERVER_TUN_IP="10.0.1.1"
CLIENT_TUN_IP="10.0.1.2"
TUN_NETMASK="255.255.255.0"
FAILURES=0
UNAVAILABLE_COUNT=0
SCENARIO_FILES=()
NETEM_ACTIVE=0
NETEM_INTERFACE_OWNED=0

# shellcheck disable=SC2329
cleanup_netem_on_exit() {
    if (( NETEM_ACTIVE == 1 && NETEM_INTERFACE_OWNED == 1 )); then
        "$TC_PATH" qdisc del dev "$NETEM_INTERFACE" root >/dev/null 2>&1 || true
    fi
}
trap cleanup_netem_on_exit EXIT

record_scenario() {
    local label="$1"; local title="$2"; shift 2
    local result="$1"; local reason="$2"; local command="$3"; shift 3
    case "$result" in
        FAIL) FAILURES=$((FAILURES + 1));;
        UNAVAILABLE) UNAVAILABLE_COUNT=$((UNAVAILABLE_COUNT + 1));;
    esac
    local file="$RUN_DIR/scenario-${label}.json"
    profile_write_scenario "$file" tun "$label" "$title" "$result" "$reason" "$command" \
        "$SOURCE_REVISION" "$EXECUTABLE_SHA256" "$HOST_NAME" "$KERNEL" "$TOOL_VERSIONS_JSON" "$PREREQUISITES_JSON" "$@"
    SCENARIO_FILES+=("$file")
}

write_csv_row() {
    local file="$1"; shift
    local first=1; local field
    for field in "$@"; do
        (( first )) || printf ',' >> "$file"
        first=0
        profile_csv_field "$field" >> "$file"
    done
    printf '\n' >> "$file"
}

# TUN runtime configuration is declared above with the preflight contract.

setup_netem() {
    local delay="$1"; local loss="$2"; local log_file="$3"
    echo "Configuring tc-netem on ${NETEM_INTERFACE}: delay=${delay} loss=${loss}"
    if "$TC_PATH" qdisc add dev "$NETEM_INTERFACE" root netem delay "$delay" loss "$loss" >"$log_file" 2>&1; then
        NETEM_ACTIVE=1
        NETEM_INTERFACE_OWNED=1
        return 0
    fi
    return $?
}

teardown_netem() {
    if (( NETEM_ACTIVE == 0 || NETEM_INTERFACE_OWNED == 0 )); then
        return 0
    fi
    echo "Removing tc-netem from ${NETEM_INTERFACE}..."
    if "$TC_PATH" qdisc del dev "$NETEM_INTERFACE" root >/dev/null 2>&1; then
        NETEM_ACTIVE=0
        NETEM_INTERFACE_OWNED=0
        return 0
    fi
    return $?
}

run_tun_scenario() {
    local label="$1"; local title="$2"; local fec_mode="$3"; local netem_delay="$4"; local netem_loss="$5"
    local csv="$RUN_DIR/scenario-${label}.csv"
    local server_log="$RUN_DIR/server-${label}.log"
    local client_log="$RUN_DIR/client-${label}.log"
    local iperf_server_log="$RUN_DIR/iperf3-server-${label}.log"
    local iperf_client_log="$RUN_DIR/iperf3-client-${label}.json"
    local netem_log="$RUN_DIR/netem-${label}.log"
    local perf_data="$RUN_DIR/perf-${label}.data"
    local perf_log="$RUN_DIR/perf-${label}.log"
    local svg="$RUN_DIR/flamegraph-${label}.svg"
    local flamegraph_log="$RUN_DIR/flamegraph-${label}.log"

    local started_at; started_at="$(profile_now_utc)"
    local server_command=("$BINARY" server --cert "$CERT" --key "$KEY" --listen 127.0.0.1:4433 --fec-mode "$fec_mode" --tun --tun-ip "$SERVER_TUN_IP" --tun-netmask "$TUN_NETMASK" -v)
    local client_command=("$BINARY" client --remote 127.0.0.1:4433 --fec-mode "$fec_mode" --tun --tun-ip "$CLIENT_TUN_IP" --tun-netmask "$TUN_NETMASK" --disable-doh -v)
    local iperf_server_command=("$IPERF3_PATH" -s -B "$CLIENT_TUN_IP")
    local iperf_client_command=("$IPERF3_PATH" -c "$CLIENT_TUN_IP" -t "$DURATION" -P 4 -J)
    local command_json; command_json="$(profile_command_bundle_json \
        "server=$(profile_command_json "${server_command[@]}")" \
        "client=$(profile_command_json "${client_command[@]}")" \
        "iperf=$(profile_command_json "${iperf_client_command[@]}")")"
    local result="PASS"; local reason=""; local metrics_status="SKIP"; local metrics_complete=false
    local perf_status="SKIP"; local flamegraph_status="SKIP"; local flamegraph_exit_status="null"; local perf_data_retained=false
    local rtt=""; local loss=""; local throughput_json="{}"; local cleanup_status="PASS"; local termination_requested=false
    local netem_setup_status="SKIP"; local netem_teardown_status="SKIP"

    printf 'scenario,label,fec_mode,netem_delay,netem_loss,result,reason,server_exit,client_exit,iperf_exit,perf_status,flamegraph_status,metrics_status,throughput_mbps,rtt,loss\n' > "$csv"
    if (( DRY_RUN )); then
        record_scenario "$label" "$title" SKIP dry_run "$command_json" \
            "$(profile_typed_pairs_json status=SKIP method=netem_process_log_traffic)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null iperf_server_pid=null iperf_client_pid=null server_exit_status=null client_exit_status=null iperf_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=SKIP complete=bool:false throughput_mbps=null rtt= loss=)" \
            "$(profile_typed_pairs_json status=SKIP netem_setup=SKIP netem_teardown=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$netem_delay" "$netem_loss" SKIP dry_run "" "" "" SKIP SKIP SKIP "" "" ""
        return
    fi
    if [[ "$PREFLIGHT_STATUS" != PASS ]]; then
        record_scenario "$label" "$title" UNAVAILABLE "$PREFLIGHT_REASON" "$command_json" \
            "$(profile_typed_pairs_json status=UNAVAILABLE method=preflight)" \
            "$(profile_typed_pairs_json server_pid=null client_pid=null iperf_server_pid=null iperf_client_pid=null server_exit_status=null client_exit_status=null iperf_exit_status=null termination_requested=bool:false)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null data_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE exit_status=null output_file=null)" \
            "$(profile_typed_pairs_json status=UNAVAILABLE complete=bool:false throughput_mbps=null rtt= loss=)" \
            "$(profile_typed_pairs_json status=SKIP netem_setup=UNAVAILABLE netem_teardown=SKIP perf_data_retained=bool:false)" \
            "$started_at" "$(profile_now_utc)"
        write_csv_row "$csv" "$label" "$label" "$fec_mode" "$netem_delay" "$netem_loss" UNAVAILABLE "$PREFLIGHT_REASON" "" "" "" UNAVAILABLE UNAVAILABLE UNAVAILABLE "" "" ""
        return
    fi

    echo "=== Scenario $label: $title ==="
    if [[ "$netem_delay" != 0ms || "$netem_loss" != 0% ]]; then
        if setup_netem "$netem_delay" "$netem_loss" "$netem_log"; then
            netem_setup_status="PASS"
        else
            netem_setup_status="FAIL"; result="FAIL"; reason="netem_setup_failed"
            record_scenario "$label" "$title" "$result" "$reason" "$command_json" \
                "$(profile_typed_pairs_json status=FAIL method=netem_setup)" \
                "$(profile_typed_pairs_json server_pid=null client_pid=null iperf_server_pid=null iperf_client_pid=null server_exit_status=null client_exit_status=null iperf_exit_status=null termination_requested=bool:false)" \
                "$(profile_typed_pairs_json status=SKIP exit_status=null data_file=null)" \
                "$(profile_typed_pairs_json status=SKIP exit_status=null output_file=null)" \
                "$(profile_typed_pairs_json status=FAIL complete=bool:false throughput_mbps=null rtt= loss=)" \
                "$(profile_typed_pairs_json status=FAIL netem_setup=FAIL netem_teardown=SKIP perf_data_retained=bool:false)" \
                "$started_at" "$(profile_now_utc)"
            write_csv_row "$csv" "$label" "$label" "$fec_mode" "$netem_delay" "$netem_loss" FAIL "$reason" "" "" "" SKIP SKIP FAIL "" "" ""
            return
        fi
    else
        netem_setup_status="PASS"
    fi

    local server_pid=""; local client_pid=""; local iperf_server_pid=""; local iperf_client_pid=""; local perf_pid=""
    local server_exit_status="null"; local client_exit_status="null"; local iperf_server_exit_status="null"; local iperf_client_exit_status="null"
    local perf_exit_status="null"; local readiness_status="SKIP"; local readiness_reason=""

    echo "  Starting the authenticated TUN endpoints..."
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
        echo "  Starting iperf3 traffic for ${DURATION}s..."
        "${iperf_server_command[@]}" >"$iperf_server_log" 2>&1 &
        iperf_server_pid=$!
        if ! profile_wait_for_pid_alive "$iperf_server_pid" "$READY_TIMEOUT"; then
            result="FAIL"
            reason="iperf_server_not_ready"
        fi
    fi

    if [[ "$result" == PASS ]]; then
        "${iperf_client_command[@]}" >"$iperf_client_log" 2>"$RUN_DIR/iperf3-client-${label}.stderr" &
        iperf_client_pid=$!
        "$PERF_PATH" record -F 99 -g -p "$server_pid" -o "$perf_data" -- sleep "$DURATION" >"$perf_log" 2>&1 &
        perf_pid=$!
        profile_wait_status "$iperf_client_pid"
        iperf_client_exit_status="$PROFILE_LAST_WAIT_STATUS"
        profile_wait_status "$perf_pid"
        perf_exit_status="$PROFILE_LAST_WAIT_STATUS"
    fi

    if [[ "$iperf_client_exit_status" == 0 ]] && \
        throughput_json="$(profile_iperf_metrics_json "$iperf_client_log" 2>"$RUN_DIR/metrics-${label}.log")"; then
        metrics_status="PASS"
        metrics_complete=true
        throughput_mbps="$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["throughput_mbps"])' "$throughput_json")"
    else
        metrics_status="FAIL"
        result="FAIL"
        [[ -n "$reason" ]] || reason="traffic_metrics_missing"
    fi

    if rtt_line="$(grep -oE 'RTT [0-9]+ ms' "$client_log" | tail -n 1)"; then
        rtt="$rtt_line"
    fi
    if loss_line="$(grep -oE 'Loss [0-9.]+%' "$client_log" | tail -n 1)"; then
        loss="$loss_line"
    fi
    if [[ -z "$rtt" || -z "$loss" ]]; then
        metrics_status="FAIL"
        metrics_complete=false
        result="FAIL"
        [[ -n "$reason" ]] || reason="required_metrics_missing"
    fi

    if [[ "$perf_exit_status" == 0 && -s "$perf_data" ]]; then
        perf_status="PASS"
        perf_data_retained=true
    else
        perf_status="FAIL"
        result="FAIL"
        [[ -n "$reason" ]] || reason="perf_capture_failed"
    fi

    if [[ "$perf_status" == PASS ]]; then
        if profile_generate_flamegraph "$PERF_PATH" "$STACKCOLLAPSE" "$FLAMEGRAPH_PL" \
            "$perf_data" "$svg" "$title (Server, TUN mode)" "$flamegraph_log"; then
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

    if [[ -n "$iperf_client_pid" ]]; then
        if profile_pid_alive "$iperf_client_pid"; then termination_requested=true; fi
        if ! profile_stop_pid "$iperf_client_pid"; then cleanup_status="FAIL"; fi
        iperf_client_exit_status="$PROFILE_LAST_WAIT_STATUS"
    fi
    if [[ -n "$iperf_server_pid" ]]; then
        if profile_pid_alive "$iperf_server_pid"; then termination_requested=true; fi
        if ! profile_stop_pid "$iperf_server_pid"; then cleanup_status="FAIL"; fi
        iperf_server_exit_status="$PROFILE_LAST_WAIT_STATUS"
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
    if ! teardown_netem; then
        netem_teardown_status="FAIL"
        cleanup_status="FAIL"
        result="FAIL"
        [[ -n "$reason" ]] || reason="netem_teardown_failed"
    else
        netem_teardown_status="PASS"
    fi
    if [[ "$cleanup_status" != PASS ]]; then
        result="FAIL"
        [[ -n "$reason" ]] || reason="cleanup_failed"
    fi

    local metrics_json
    metrics_json="$(profile_typed_pairs_json status="$metrics_status" complete="bool:$metrics_complete" throughput_mbps="${throughput_mbps:-}" rtt="$rtt" loss="$loss")"
    local process_json
    process_json="$(profile_typed_pairs_json server_pid="${server_pid:-null}" client_pid="${client_pid:-null}" iperf_server_pid="${iperf_server_pid:-null}" iperf_client_pid="${iperf_client_pid:-null}" server_exit_status="${server_exit_status:-null}" client_exit_status="${client_exit_status:-null}" iperf_server_exit_status="${iperf_server_exit_status:-null}" iperf_client_exit_status="${iperf_client_exit_status:-null}" termination_requested="bool:$termination_requested")"
    record_scenario "$label" "$title" "$result" "${reason:-completed}" "$command_json" \
        "$(profile_typed_pairs_json status="$readiness_status" reason="$readiness_reason" server_log="$server_log" client_log="$client_log")" \
        "$process_json" \
        "$(profile_typed_pairs_json status="$perf_status" exit_status="${perf_exit_status:-null}" data_file="$perf_data" retained="bool:$perf_data_retained")" \
        "$(profile_typed_pairs_json status="$flamegraph_status" exit_status="$flamegraph_exit_status" output_file="$svg")" \
        "$metrics_json" \
        "$(profile_typed_pairs_json status="$cleanup_status" netem_setup="$netem_setup_status" netem_teardown="$netem_teardown_status" perf_data_retained="bool:$perf_data_retained")" \
        "$started_at" "$(profile_now_utc)"
    write_csv_row "$csv" "$label" "$label" "$fec_mode" "$netem_delay" "$netem_loss" "$result" "${reason:-completed}" "$server_exit_status" "$client_exit_status" "$iperf_client_exit_status" "$perf_status" "$flamegraph_status" "$metrics_status" "${throughput_mbps:-}" "$rtt" "$loss"
}

echo "=== QuicFuscate TUN-mode Profiling ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Duration per scenario: ${DURATION}s"

for label in "${SCENARIO_LABELS[@]}"; do
    [[ -z "$SCENARIO_FILTER" || "$label" == "$SCENARIO_FILTER" ]] || continue
    case "$label" in
        g) run_tun_scenario "g" "TUN data plane (FEC auto, no loss)" auto 0ms 0%;;
        h) run_tun_scenario "h" "TUN data plane (FEC auto, 50ms delay)" auto 50ms 0%;;
        i) run_tun_scenario "i" "TUN data plane (FEC auto, 5% loss)" auto 0ms 5%;;
        j) run_tun_scenario "j" "TUN data plane (FEC auto, 50ms plus 5% loss)" auto 50ms 5%;;
        k) run_tun_scenario "k" "TUN data plane (FEC off, 5% loss)" off 0ms 5%;;
    esac
done

profile_write_manifest "$MANIFEST" tun "$OUTPUT_DIR" "$SOURCE_REVISION" "$EXECUTABLE_SHA256" \
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
