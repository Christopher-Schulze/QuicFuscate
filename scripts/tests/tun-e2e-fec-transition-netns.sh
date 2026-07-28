#!/usr/bin/env bash
# FEC policy and mode transition E2E test via tc-netem (TODO-427, TODO-558).
#
# `TRANSITION_SCENARIOS` is the single source for every profile's real-load
# phase inputs, observed-loss bounds, recovery settle, quantitative recovery
# duration, and Fountain policy.
#
# Off remains Zero with no repairs or switches. Auto remains Zero while clean,
# adapts with repairs under loss, and returns to Zero during the bounded recovery.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="$PROJECT_ROOT/config/local/ca.crt"
CA_KEY="$PROJECT_ROOT/config/local/ca.key"
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
FEC_MODE="${FEC_MODE:-auto}"
TELEMETRY_PORT="${QF_FEC_TELEMETRY_PORT:-9898}"
LOSS_PROFILE="${QF_FEC_LOSS_PROFILE:-moderate}"
EVIDENCE_DIR="${QF_E2E_ARTIFACT_DIR:-}"
CRYPTO_FAILURE_PATTERN='Crypto error: crypto failure|AEAD limit reached|Key update error'
TRANSITION_SCENARIOS=(
    "moderate:20:35:50:5:150:10:250:10:40000:1"
    "severe:40:60:50:5:150:10:250:10:40000:0"
)
TRANSITION_SCENARIO=""
LOSS_PERCENT=""
MAX_TUNNEL_LOSS_PERCENT=""
CLEAN_PING_COUNT=""
CLEAN_MAX_TUNNEL_LOSS_PERCENT=""
LOSS_PHASE_PING_COUNT=""
RECOVERY_SETTLE_SECONDS=""
RECOVERY_PING_COUNT=""
RECOVERY_MAX_TUNNEL_LOSS_PERCENT=""
MAX_RECOVERY_DURATION_MS=""
FORBID_FOUNTAIN=""

for scenario in "${TRANSITION_SCENARIOS[@]}"; do
    IFS=':' read -r profile_name loss_percent max_tunnel_loss_percent \
        clean_ping_count clean_max_tunnel_loss_percent loss_phase_ping_count \
        recovery_settle_seconds recovery_ping_count recovery_max_tunnel_loss_percent \
        max_recovery_duration_ms forbid_fountain <<< "$scenario"
    if [ "$profile_name" = "$LOSS_PROFILE" ]; then
        TRANSITION_SCENARIO="$scenario"
        LOSS_PERCENT="$loss_percent"
        MAX_TUNNEL_LOSS_PERCENT="$max_tunnel_loss_percent"
        CLEAN_PING_COUNT="$clean_ping_count"
        CLEAN_MAX_TUNNEL_LOSS_PERCENT="$clean_max_tunnel_loss_percent"
        LOSS_PHASE_PING_COUNT="$loss_phase_ping_count"
        RECOVERY_SETTLE_SECONDS="$recovery_settle_seconds"
        RECOVERY_PING_COUNT="$recovery_ping_count"
        RECOVERY_MAX_TUNNEL_LOSS_PERCENT="$recovery_max_tunnel_loss_percent"
        MAX_RECOVERY_DURATION_MS="$max_recovery_duration_ms"
        FORBID_FOUNTAIN="$forbid_fountain"
        break
    fi
done

if [ -z "$TRANSITION_SCENARIO" ]; then
    echo "FAIL: QF_FEC_LOSS_PROFILE must select a declared transition scenario" >&2
    exit 2
fi

PASS=0
FAIL=0
SERVER_PID=""
CLIENT_PID=""
SERVER_NAMESPACE_CREATED=0
CLIENT_NAMESPACE_CREATED=0
VETH_CREATED=0
QDISC_CREATED=0
RUNTIME_DIR=""
CURRENT_SCENARIO_DIR=""
SERVER_LOG=""
CLIENT_LOG=""
SERVER_TELEMETRY=""
CLIENT_TELEMETRY=""
ADMIN_SOCKET=""
QKEY_STORE=""
CERT=""
KEY=""
RECOVERY_DURATION_MS=""

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
    echo "FAIL: could not acquire TUN E2E lock $LOCK_FILE within ${LOCK_TIMEOUT}s" >&2
    exit 2
fi

stop_owned_process() {
    local pid="$1"
    if [ -z "$pid" ]; then
        return
    fi

    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
    if kill -0 "$pid" 2>/dev/null; then
        echo "FAIL: owned child $pid survived exact cleanup" >&2
        return 1
    fi
}

remove_qdisc() {
    if [ "$QDISC_CREATED" = "1" ] && [ "$CLIENT_NAMESPACE_CREATED" = "1" ]; then
        if ! ip netns exec ns-cli tc qdisc del dev veth-cli root 2>/dev/null; then
            echo "FAIL: owned qdisc survived exact cleanup" >&2
            return 1
        fi
    fi
    QDISC_CREATED=0
}

cleanup_owned_resources() {
    local cleanup_failed=0
    remove_qdisc || cleanup_failed=1
    stop_owned_process "$CLIENT_PID" || cleanup_failed=1
    CLIENT_PID=""
    stop_owned_process "$SERVER_PID" || cleanup_failed=1
    SERVER_PID=""

    if [ "$CLIENT_NAMESPACE_CREATED" = "1" ]; then
        ip netns del ns-cli 2>/dev/null || true
        if ip netns list | grep -Eq '^ns-cli([[:space:]]|$)'; then
            echo "FAIL: owned client namespace survived cleanup" >&2
            cleanup_failed=1
        else
            CLIENT_NAMESPACE_CREATED=0
        fi
    fi
    if [ "$SERVER_NAMESPACE_CREATED" = "1" ]; then
        ip netns del ns-srv 2>/dev/null || true
        if ip netns list | grep -Eq '^ns-srv([[:space:]]|$)'; then
            echo "FAIL: owned server namespace survived cleanup" >&2
            cleanup_failed=1
        else
            SERVER_NAMESPACE_CREATED=0
        fi
    fi
    if [ "$VETH_CREATED" = "1" ]; then
        ip link del veth-cli 2>/dev/null || ip link del veth-srv 2>/dev/null || true
        if ip link show dev veth-srv >/dev/null 2>&1 || ip link show dev veth-cli >/dev/null 2>&1; then
            echo "FAIL: owned veth link survived cleanup" >&2
            cleanup_failed=1
        else
            VETH_CREATED=0
        fi
    fi
    return "$cleanup_failed"
}

remove_runtime_dir() {
    if [ -z "$RUNTIME_DIR" ]; then
        return
    fi
    case "$RUNTIME_DIR" in
        /tmp/quicfuscate-fec-transition.*)
            rm -rf -- "$RUNTIME_DIR"
            ;;
        *)
            echo "FAIL: refusing to remove unexpected runtime path: $RUNTIME_DIR" >&2
            return 1
            ;;
    esac
    RUNTIME_DIR=""
}

preserve_evidence() {
    local clean_loss="$1"
    local impaired_loss="$2"
    local recovered_loss="$3"
    local panic_count
    local decrypt_failure_count
    if [ -z "$EVIDENCE_DIR" ]; then
        return
    fi
    if [ -e "$EVIDENCE_DIR" ]; then
        fatal "refusing to overwrite existing evidence path: $EVIDENCE_DIR"
    fi
    if [ ! -d "$(dirname "$EVIDENCE_DIR")" ]; then
        fatal "evidence parent directory does not exist: $(dirname "$EVIDENCE_DIR")"
    fi
    mkdir "$EVIDENCE_DIR" || fatal "could not create evidence directory: $EVIDENCE_DIR"
    cp -- "$CURRENT_SCENARIO_DIR"/*.telemetry "$SERVER_LOG" "$CLIENT_LOG" "$EVIDENCE_DIR/" \
        || fatal "could not preserve runtime evidence"
    panic_count=$(grep -ci 'panic' "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null \
        | awk -F: '{ sum += $NF } END { print sum + 0 }')
    decrypt_failure_count=$(grep -Eci "$CRYPTO_FAILURE_PATTERN" \
        "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null \
        | awk -F: '{ sum += $NF } END { print sum + 0 }')
    {
        printf 'policy=%s\n' "$FEC_MODE"
        printf 'transition_scenario=%s\n' "$TRANSITION_SCENARIO"
        printf 'loss_profile=%s\n' "$LOSS_PROFILE"
        printf 'netem_loss_percent=%s\n' "$LOSS_PERCENT"
        printf 'max_tunnel_loss_percent=%s\n' "$MAX_TUNNEL_LOSS_PERCENT"
        printf 'clean_ping_count=%s\n' "$CLEAN_PING_COUNT"
        printf 'clean_max_tunnel_loss_percent=%s\n' "$CLEAN_MAX_TUNNEL_LOSS_PERCENT"
        printf 'loss_phase_ping_count=%s\n' "$LOSS_PHASE_PING_COUNT"
        printf 'recovery_settle_seconds=%s\n' "$RECOVERY_SETTLE_SECONDS"
        printf 'recovery_ping_count=%s\n' "$RECOVERY_PING_COUNT"
        printf 'recovery_max_tunnel_loss_percent=%s\n' "$RECOVERY_MAX_TUNNEL_LOSS_PERCENT"
        printf 'max_recovery_duration_ms=%s\n' "$MAX_RECOVERY_DURATION_MS"
        printf 'forbid_fountain=%s\n' "$FORBID_FOUNTAIN"
        printf 'clean_tunnel_loss_percent=%s\n' "$clean_loss"
        printf 'impaired_tunnel_loss_percent=%s\n' "$impaired_loss"
        printf 'recovered_tunnel_loss_percent=%s\n' "$recovered_loss"
        printf 'recovery_duration_ms=%s\n' "$RECOVERY_DURATION_MS"
        printf 'server_handshakes=%s\n' "$(grep -c 'TLS handshake complete' "$SERVER_LOG")"
        printf 'client_handshakes=%s\n' "$(grep -c 'TLS handshake complete' "$CLIENT_LOG")"
        printf 'panic_count=%s\n' "$panic_count"
        printf 'decrypt_failure_count=%s\n' "$decrypt_failure_count"
        printf 'binary_sha256=%s\n' "$(sha256sum "$B" | awk '{print $1}')"
    } > "$EVIDENCE_DIR/run-manifest.txt" \
        || fatal "could not preserve evidence manifest"
    echo "Evidence: $EVIDENCE_DIR"
}

# Invoked by the EXIT trap below.
# shellcheck disable=SC2329
cleanup_on_exit() {
    local status=$?
    if [ "$status" -ne 0 ] && [ "$KEEP_ON_FAIL" = "1" ]; then
        echo "QF_E2E_KEEP_ON_FAIL=1: preserving owned runtime resources in ${RUNTIME_DIR:-<none>}" >&2
        return
    fi
    cleanup_owned_resources || true
    remove_runtime_dir || true
}

dump_diagnostics() {
    echo "=== failure diagnostics: TUN link counters ===" >&2
    ip netns exec ns-srv ip -s link show qtun0 >&2 2>/dev/null || true
    ip netns exec ns-cli ip -s link show qtun0 >&2 2>/dev/null || true
    echo "=== failure diagnostics: server log ===" >&2
    tail -80 "$SERVER_LOG" >&2 2>/dev/null || true
    echo "=== failure diagnostics: client log ===" >&2
    tail -80 "$CLIENT_LOG" >&2 2>/dev/null || true
}

fatal() {
    echo "FAIL: $*" >&2
    dump_diagnostics
    exit 1
}

preserve_failure_if_requested() {
    if [ "$KEEP_ON_FAIL" = "1" ] && [ "$FAIL" -gt 0 ]; then
        dump_diagnostics
        echo "QF_E2E_KEEP_ON_FAIL=1: stopping after the first recorded failure" >&2
        exit 1
    fi
}

run_ownership_self_test() {
    local pid_file="${QF_E2E_OWNERSHIP_PID_FILE:-}"
    sleep 300 &
    SERVER_PID=$!
    sleep 300 &
    CLIENT_PID=$!
    if [ -n "$pid_file" ]; then
        printf '%s\n' "$SERVER_PID" "$CLIENT_PID" > "$pid_file"
    fi
    case "${QF_E2E_OWNERSHIP_SELF_TEST_MODE:-exit}" in
        exit) exit 23 ;;
        signal) kill -TERM "$$"; sleep 1; exit 99 ;;
        keep) KEEP_ON_FAIL=1; exit 24 ;;
        *) echo "FAIL: unknown ownership self-test mode" >&2; exit 2 ;;
    esac
}

# Fail closed before touching certificates or runtime resources.
if [ "$(id -u)" -ne 0 ]; then
    echo "FAIL: this harness requires root" >&2
    exit 2
fi
if [ "$FEC_MODE" != "off" ] && [ "$FEC_MODE" != "auto" ]; then
    echo "FAIL: FEC_MODE must be 'off' or 'auto'" >&2
    exit 2
fi
if [ -n "$EVIDENCE_DIR" ] && [ "${EVIDENCE_DIR#/}" = "$EVIDENCE_DIR" ]; then
    echo "FAIL: QF_E2E_ARTIFACT_DIR must be an absolute path" >&2
    exit 2
fi
if [ -n "$EVIDENCE_DIR" ] && [ -e "$EVIDENCE_DIR" ]; then
    echo "FAIL: refusing to overwrite existing evidence path: $EVIDENCE_DIR" >&2
    exit 2
fi
if [ -n "$EVIDENCE_DIR" ] && [ ! -d "$(dirname "$EVIDENCE_DIR")" ]; then
    echo "FAIL: evidence parent directory does not exist: $(dirname "$EVIDENCE_DIR")" >&2
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "FAIL: required command not found: sha256sum" >&2
    exit 2
fi
if pgrep -x quicfuscate >/dev/null; then
    echo "FAIL: a pre-existing quicfuscate process is running; refusing broad cleanup" >&2
    exit 2
fi
if ip netns list | grep -Eq '^(ns-srv|ns-cli)([[:space:]]|$)'; then
    echo "FAIL: ns-srv or ns-cli already exists; refusing to delete an unowned namespace" >&2
    exit 2
fi
if ip link show dev veth-srv >/dev/null 2>&1 || ip link show dev veth-cli >/dev/null 2>&1; then
    echo "FAIL: veth-srv or veth-cli already exists; refusing to delete an unowned link" >&2
    exit 2
fi
trap cleanup_on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

if [ "${QF_E2E_OWNERSHIP_SELF_TEST:-0}" = "1" ]; then
    run_ownership_self_test
fi

[ -x "$B" ] || fatal "release artifact is not executable: $B"
[ -r "$CA" ] || fatal "CA certificate is not readable: $CA"
[ -r "$CA_KEY" ] || fatal "CA key is not readable: $CA_KEY"
modprobe sch_netem 2>/dev/null || true
RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-fec-transition.XXXXXX)" || fatal "could not create runtime directory"
CERT="$RUNTIME_DIR/server.crt"
KEY="$RUNTIME_DIR/server.key"
LEAF_CERT="$RUNTIME_DIR/leaf.crt"
CSR="$RUNTIME_DIR/server.csr"
CERT_EXT="$RUNTIME_DIR/leaf-ext.cnf"
CA_SERIAL="$RUNTIME_DIR/ca.srl"

cat > "$CERT_EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:10.10.0.1
EOF
openssl req -newkey rsa:2048 -keyout "$KEY" -out "$CSR" -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null \
    || fatal "could not generate the isolated server key"
openssl x509 -req -in "$CSR" -CA "$CA" -CAkey "$CA_KEY" -CAserial "$CA_SERIAL" \
    -CAcreateserial -out "$LEAF_CERT" -days 365 -extfile "$CERT_EXT" 2>/dev/null \
    || fatal "could not sign the isolated server certificate"
cat "$LEAF_CERT" "$CA" > "$CERT" || fatal "could not assemble the isolated certificate chain"

prepare_scenario_runtime() {
    local scenario="$1"
    CURRENT_SCENARIO_DIR="$RUNTIME_DIR/$scenario"
    if [ -e "$CURRENT_SCENARIO_DIR" ]; then
        fatal "scenario runtime already exists: $CURRENT_SCENARIO_DIR"
    fi
    mkdir "$CURRENT_SCENARIO_DIR" || fatal "could not create scenario runtime: $scenario"
    SERVER_LOG="$CURRENT_SCENARIO_DIR/server.log"
    CLIENT_LOG="$CURRENT_SCENARIO_DIR/client.log"
    ADMIN_SOCKET="$CURRENT_SCENARIO_DIR/admin.sock"
    QKEY_STORE="$CURRENT_SCENARIO_DIR/qkeys.json"
}

setup_netns() {
    ip netns add ns-srv || fatal "could not create server namespace"
    SERVER_NAMESPACE_CREATED=1
    ip netns add ns-cli || fatal "could not create client namespace"
    CLIENT_NAMESPACE_CREATED=1
    ip link add veth-srv type veth peer name veth-cli || fatal "could not create veth pair"
    VETH_CREATED=1
    ip link set veth-srv netns ns-srv || fatal "could not move server veth"
    ip link set veth-cli netns ns-cli || fatal "could not move client veth"
    ip netns exec ns-srv ip addr add 10.10.0.1/24 dev veth-srv || fatal "could not address server veth"
    ip netns exec ns-srv ip link set veth-srv up || fatal "could not activate server veth"
    ip netns exec ns-srv ip link set lo up || fatal "could not activate server loopback"
    ip netns exec ns-srv ip route add default dev veth-srv || fatal "could not add server default route"
    ip netns exec ns-cli ip addr add 10.10.0.2/24 dev veth-cli || fatal "could not address client veth"
    ip netns exec ns-cli ip link set veth-cli up || fatal "could not activate client veth"
    ip netns exec ns-cli ip link set lo up || fatal "could not activate client loopback"
}

start_tunnel() {
    ip netns exec ns-srv env QUICFUSCATE_METRICS_ADDR="127.0.0.1:${TELEMETRY_PORT}" \
        "$B" --telemetry server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket "$ADMIN_SOCKET" \
        --qkey-store "$QKEY_STORE" \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
        --fec-mode "$FEC_MODE" --no-drop-privileges -v \
        > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 3

    local qkey
    qkey=$(echo '{"cmd":"qkey"}' | nc -U "$ADMIN_SOCKET" 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)
    if [ -z "$qkey" ]; then
        fatal "could not get qkey from server"
    fi

    ip netns exec ns-cli env QUICFUSCATE_METRICS_ADDR="127.0.0.1:${TELEMETRY_PORT}" \
        "$B" --telemetry client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
        --qkey "$qkey" --ca-file "$CA" --verify-peer \
        --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 \
        --fec-mode "$FEC_MODE" --no-utls -v \
        > "$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
    sleep 4

    ip netns exec ns-srv ip addr add 10.0.1.1/24 dev qtun0 2>/dev/null
    ip netns exec ns-srv ip link set qtun0 up 2>/dev/null
    ip netns exec ns-cli ip addr add 10.0.1.2/24 dev qtun0 2>/dev/null
    ip netns exec ns-cli ip link set qtun0 up 2>/dev/null
    sleep 2
}

check_handshake() {
    local cli srv
    cli=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli=${cli:-0}
    srv=${srv:-0}
    [ "$cli" -gt 0 ] && [ "$srv" -gt 0 ]
}

fetch_telemetry() {
    local namespace="$1"
    local output_path="$2"
    ip netns exec "$namespace" python3 -c \
        'import sys,urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=3).read().decode())' \
        "http://127.0.0.1:${TELEMETRY_PORT}/telemetry" > "$output_path" 2>/dev/null
}

metric_value() {
    local file="$1"
    local metric="$2"
    awk -v metric="$metric" '$1 == metric { print $2; found=1; exit } END { if (!found) exit 1 }' "$file"
}

monotonic_milliseconds() {
    python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
}

capture_telemetry_phase() {
    local phase="$1"
    SERVER_TELEMETRY="$CURRENT_SCENARIO_DIR/server-${phase}.telemetry"
    CLIENT_TELEMETRY="$CURRENT_SCENARIO_DIR/client-${phase}.telemetry"
    fetch_telemetry ns-srv "$SERVER_TELEMETRY" \
        || fatal "server telemetry endpoint unavailable in ns-srv during ${phase}"
    fetch_telemetry ns-cli "$CLIENT_TELEMETRY" \
        || fatal "client telemetry endpoint unavailable in ns-cli during ${phase}"

    local file mode_id mode_name metric
    for file in "$SERVER_TELEMETRY" "$CLIENT_TELEMETRY"; do
        for mode_id in {0..8}; do
            case "$mode_id" in
                0) mode_name="zero" ;;
                1) mode_name="light" ;;
                2) mode_name="normal" ;;
                3) mode_name="medium" ;;
                4) mode_name="strong" ;;
                5) mode_name="extreme" ;;
                6) mode_name="ultra" ;;
                7) mode_name="fountain" ;;
                8) mode_name="streaming" ;;
            esac
            metric_value "$file" \
                "quicfuscate_fec_active_connections{mode=\"${mode_name}\",mode_id=\"${mode_id}\"}" \
                >/dev/null || fatal "missing stable FEC mode mapping ${mode_name}=${mode_id}"
        done
        local active
        active=$(metric_value "$file" "quicfuscate_fec_active_connections_total") \
            || fatal "missing active FEC connection aggregate"
        [ "$active" -ge 1 ] || fatal "telemetry endpoint has no active FEC connection"
        for metric in \
            quicfuscate_fec_source_payload_bytes_sent_total \
            quicfuscate_fec_source_wire_bytes_sent_total \
            quicfuscate_fec_repair_wire_bytes_sent_total \
            quicfuscate_fec_wire_overhead_sent_ppm \
            quicfuscate_fec_recovered_packets_total \
            quicfuscate_fec_recovered_payload_bytes_total
        do
            metric_value "$file" "$metric" >/dev/null \
                || fatal "missing quantitative FEC metric ${metric} during ${phase}"
        done
    done
}

assert_zero_no_repair_snapshot() {
    local file="$1"
    local zero_active repairs switches overhead nonzero_active
    zero_active=$(metric_value "$file" \
        'quicfuscate_fec_active_connections{mode="zero",mode_id="0"}') \
        || fatal "missing Zero mode bucket"
    repairs=$(metric_value "$file" "quicfuscate_fec_repair_packets_sent_total") \
        || fatal "missing repair send counter"
    switches=$(metric_value "$file" "quicfuscate_fec_mode_switches_total") \
        || fatal "missing mode switch counter"
    overhead=$(metric_value "$file" "quicfuscate_fec_wire_overhead_sent_ppm") \
        || fatal "missing FEC wire-overhead counter"
    nonzero_active=$(awk '
        /^quicfuscate_fec_active_connections\{mode=/ &&
        $1 !~ /mode="zero"/ { sum += $2 }
        END { print sum + 0 }
    ' "$file")
    [ "$zero_active" -ge 1 ] || return 1
    [ "$nonzero_active" -eq 0 ] || return 1
    [ "$repairs" -eq 0 ] || return 1
    [ "$switches" -eq 0 ] || return 1
    [ "$overhead" -eq 0 ] || return 1
}

assert_zero_mode_snapshot() {
    local file="$1"
    local zero_active nonzero_active
    zero_active=$(metric_value "$file" \
        'quicfuscate_fec_active_connections{mode="zero",mode_id="0"}') \
        || fatal "missing Zero mode bucket"
    nonzero_active=$(awk '
        /^quicfuscate_fec_active_connections\{mode=/ &&
        $1 !~ /mode="zero"/ { sum += $2 }
        END { print sum + 0 }
    ' "$file")
    [ "$zero_active" -ge 1 ] || return 1
    [ "$nonzero_active" -eq 0 ] || return 1
}

ping_phase() {
    local count="$1"
    local label="$2"
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$count" -i 0.1 -W 5 -I qtun0 10.0.1.1 2>&1)
    local ping_loss
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    echo "  Phase ${label}: ${ping_loss}% tunnel loss" >&2
    echo "$ping_loss"
}

echo "=== FEC Policy/Transition E2E Test (TODO-427, TODO-558) ==="
echo "Policy: $FEC_MODE"
echo "Transition contract: ${TRANSITION_SCENARIOS[*]} (profile:netem-loss:max-tunnel-loss:clean-pings:clean-max-loss:loss-pings:recovery-settle:recovery-pings:recovery-max-loss:max-recovery-ms:forbid-fountain)"
echo "Selected transition profile: $TRANSITION_SCENARIO"

prepare_scenario_runtime "transition"
setup_netns
start_tunnel

if ! check_handshake; then
    echo "FAIL: handshake failed"
    FAIL=$((FAIL + 1))
    exit 1
fi

# Phase 1: Clean link without applied netem loss.
echo "Phase 1: Clean link (0% loss)..."
loss1=$(ping_phase "$CLEAN_PING_COUNT" "1")
capture_telemetry_phase "clean"

# Phase 2: Inject the selected loss profile and observe the live policy.
echo "Phase 2: Inject ${LOSS_PERCENT}% ${LOSS_PROFILE} loss..."
if ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss "${LOSS_PERCENT}%"; then
    QDISC_CREATED=1
else
    fatal "could not apply ${LOSS_PERCENT}% netem loss"
fi
sleep 2  # Let FEC detect loss and start transition
loss2=$(ping_phase "$LOSS_PHASE_PING_COUNT" "2")
capture_telemetry_phase "lossy"
client_lossy_overhead=$(metric_value \
    "$CURRENT_SCENARIO_DIR/client-lossy.telemetry" \
    "quicfuscate_fec_wire_overhead_sent_ppm") || fatal "missing lossy client FEC wire-overhead"
remove_qdisc || fatal "could not remove transition netem loss"

# Phase 3: Remove loss - FEC de-escalates (live transition)
echo "Phase 3: Remove loss (FEC de-escalates)..."
recovery_started_ms=$(monotonic_milliseconds) || fatal "could not read recovery monotonic clock"
sleep "$RECOVERY_SETTLE_SECONDS"
loss3=$(ping_phase "$RECOVERY_PING_COUNT" "3")
capture_telemetry_phase "recovered"
recovery_finished_ms=$(monotonic_milliseconds) || fatal "could not read recovery monotonic clock"
RECOVERY_DURATION_MS=$((recovery_finished_ms - recovery_started_ms))

# Acceptance criteria
echo ""
echo "Results:"
echo "  Phase 1 (clean):     ${loss1}% loss"
echo "  Phase 2 (${LOSS_PROFILE}, ${LOSS_PERCENT}% loss): ${loss2}% loss"
echo "  Phase 3 (recovered): ${loss3}% loss"
echo "  Recovery duration: ${RECOVERY_DURATION_MS} ms"

ok=true
if [ "$loss1" -gt "$CLEAN_MAX_TUNNEL_LOSS_PERCENT" ]; then
    echo "FAIL: Phase 1 loss >${CLEAN_MAX_TUNNEL_LOSS_PERCENT}%"
    ok=false
fi
if [ "$loss2" -gt "$MAX_TUNNEL_LOSS_PERCENT" ]; then
    echo "FAIL: Phase 2 loss >${MAX_TUNNEL_LOSS_PERCENT}%"
    ok=false
fi
if [ "$loss3" -gt "$RECOVERY_MAX_TUNNEL_LOSS_PERCENT" ]; then
    echo "FAIL: Phase 3 loss >${RECOVERY_MAX_TUNNEL_LOSS_PERCENT}% during clean-link recovery"
    ok=false
fi
if [ "$RECOVERY_DURATION_MS" -gt "$MAX_RECOVERY_DURATION_MS" ]; then
    echo "FAIL: Recovery duration ${RECOVERY_DURATION_MS}ms >${MAX_RECOVERY_DURATION_MS}ms"
    ok=false
fi

if [ "$FEC_MODE" = "off" ]; then
    for snapshot in \
        "$CURRENT_SCENARIO_DIR/server-clean.telemetry" \
        "$CURRENT_SCENARIO_DIR/client-clean.telemetry" \
        "$CURRENT_SCENARIO_DIR/server-lossy.telemetry" \
        "$CURRENT_SCENARIO_DIR/client-lossy.telemetry" \
        "$CURRENT_SCENARIO_DIR/server-recovered.telemetry" \
        "$CURRENT_SCENARIO_DIR/client-recovered.telemetry"
    do
        if ! assert_zero_no_repair_snapshot "$snapshot"; then
            echo "FAIL: Off policy emitted repairs, switched mode, or left Zero in $snapshot"
            ok=false
        fi
    done
else
    for snapshot in \
        "$CURRENT_SCENARIO_DIR/server-clean.telemetry" \
        "$CURRENT_SCENARIO_DIR/client-clean.telemetry"
    do
        if ! assert_zero_no_repair_snapshot "$snapshot"; then
            echo "FAIL: Auto policy spent FEC work, emitted wire overhead, or left Zero on the clean link in $snapshot"
            ok=false
        fi
    done

    client_nonzero_active=$(awk '
        /^quicfuscate_fec_active_connections\{mode=/ &&
        $1 !~ /mode="zero"/ { sum += $2 }
        END { print sum + 0 }
    ' "$CURRENT_SCENARIO_DIR/client-lossy.telemetry")
    client_repairs=$(metric_value \
        "$CURRENT_SCENARIO_DIR/client-recovered.telemetry" \
        "quicfuscate_fec_repair_packets_sent_total") || client_repairs=0
    client_switches=$(metric_value \
        "$CURRENT_SCENARIO_DIR/client-lossy.telemetry" \
        "quicfuscate_fec_mode_switches_total") || client_switches=0
    if [ "$client_nonzero_active" -le 0 ] || [ "$client_switches" -le 0 ]; then
        echo "FAIL: Auto policy committed no non-Zero client adaptation under loss"
        ok=false
    fi
    if [ "$client_lossy_overhead" -le 0 ]; then
        echo "FAIL: Auto policy reported no positive FEC wire overhead under loss"
        ok=false
    fi
    if [ "$client_repairs" -le 0 ]; then
        echo "FAIL: Auto policy produced no client repair by the end of the run"
        ok=false
    fi
    if ! assert_zero_mode_snapshot "$CURRENT_SCENARIO_DIR/client-recovered.telemetry"; then
        echo "FAIL: Auto policy did not return to Zero within the bounded recovery phase"
        ok=false
    fi

    if [ "$FORBID_FOUNTAIN" = "1" ]; then
        client_fountain_active=$(metric_value \
            "$CURRENT_SCENARIO_DIR/client-lossy.telemetry" \
            'quicfuscate_fec_active_connections{mode="fountain",mode_id="7"}') \
            || client_fountain_active=0
        client_extreme_switches=$(metric_value \
            "$CURRENT_SCENARIO_DIR/client-recovered.telemetry" \
            "quicfuscate_fec_switch_reason_extreme_total") || client_extreme_switches=0
        if [ "$client_fountain_active" -gt 0 ] || [ "$client_extreme_switches" -gt 0 ]; then
            echo "FAIL: moderate loss incorrectly selected the Fountain rescue tier"
            ok=false
        fi
    fi
fi

if $ok; then
    echo "PASS: ${FEC_MODE} policy and telemetry contract held under load"
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

if grep -q 'panic' "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
    echo "FAIL: panic detected"
    FAIL=$((FAIL + 1))
fi
if grep -Eqi "$CRYPTO_FAILURE_PATTERN" "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
    echo "FAIL: transport decryption failure detected"
    FAIL=$((FAIL + 1))
fi

preserve_failure_if_requested
cleanup_owned_resources || fatal "could not clean final owned resources"
preserve_evidence "$loss1" "$loss2" "$loss3"

echo ""
echo "=========================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
remove_runtime_dir || fatal "could not remove isolated runtime directory"
trap - EXIT INT TERM
exit 0
