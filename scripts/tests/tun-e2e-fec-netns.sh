#!/usr/bin/env bash
# End-to-end FEC test through real QUIC transport with tc-netem loss injection.
#
# Two network namespaces over veth, QUIC tunnel with TUN, ping through the
# tunnel via MASQUE CONNECT-UDP. tc-netem injects controlled packet loss on
# the veth interface to test FEC recovery end-to-end.
#
# Executable acceptance (TODO-423):
#   - UNIFORM_PING_SCENARIOS is the single source for executed netem loss and
#     bounded tunnel-loss cases.
#   - UNIFORM_IPERF_SCENARIOS is the single source for receiver-verified
#     throughput cases.
#   - No panics or crashes.
#
# Requirements: root, Linux, iproute2, tc-netem, coreutils timeout, openssl,
# python3, nc, iperf3.
# Run on the target server (e.g. broderick).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="$PROJECT_ROOT/config/local/ca.crt"
CA_KEY="$PROJECT_ROOT/config/local/ca.key"

UNIFORM_PING_SCENARIOS=(
    "0:0"
    "5:15"
    "10:20"
    "25:40"
)
UNIFORM_IPERF_SCENARIOS=(0 10)
PING_COUNT="${PING_COUNT:-100}"
PING_INTERVAL="${PING_INTERVAL:-0.1}"
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-fec-uniform-evidence-$$}"
RUNTIME_FAILURE_PATTERN='panic|Crypto error: crypto failure|AEAD limit reached|Key update error|heartbeat timeout|InternalError|TUN packet send failed'

PASS=0
FAIL=0
SERVER_PID=""
CLIENT_PID=""
IPERF_SERVER_PID=""
SERVER_NAMESPACE_CREATED=0
CLIENT_NAMESPACE_CREATED=0
VETH_CREATED=0
QDISC_CREATED=0
RUNTIME_DIR=""
CURRENT_SCENARIO_DIR=""
SERVER_LOG=""
CLIENT_LOG=""
IPERF_LOG=""
ADMIN_SOCKET=""
QKEY_STORE=""
CERT=""
KEY=""

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
    stop_owned_process "$IPERF_SERVER_PID" || cleanup_failed=1
    IPERF_SERVER_PID=""
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
        /tmp/quicfuscate-fec-netns.*)
            rm -rf -- "$RUNTIME_DIR"
            ;;
        *)
            echo "FAIL: refusing to remove unexpected runtime path: $RUNTIME_DIR" >&2
            return 1
            ;;
    esac
    RUNTIME_DIR=""
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

record_result() {
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" \
        >> "$ARTIFACT_DIR/results.tsv" \
        || fatal "could not append uniform evidence result"
}

check_runtime_logs() {
    local scenario="$1"
    local matches="$ARTIFACT_DIR/runtime-errors-${scenario}.txt"
    if grep -EHi "$RUNTIME_FAILURE_PATTERN" "$SERVER_LOG" "$CLIENT_LOG" > "$matches" 2>/dev/null; then
        echo "FAIL: ${scenario} logs contain a panic, decryption, heartbeat, internal, or TUN-send failure"
        FAIL=$((FAIL + 1))
        record_result runtime "$scenario" detected 0 fail
        return 1
    fi
    rm -f -- "$matches"
    record_result runtime "$scenario" 0 0 pass
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
    sleep 300 &
    IPERF_SERVER_PID=$!
    if [ -n "$pid_file" ]; then
        printf '%s\n' "$SERVER_PID" "$CLIENT_PID" "$IPERF_SERVER_PID" > "$pid_file"
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
if [ "${ARTIFACT_DIR#/}" = "$ARTIFACT_DIR" ]; then
    echo "FAIL: QF_E2E_ARTIFACT_DIR must be an absolute path" >&2
    exit 2
fi
if [ -e "$ARTIFACT_DIR" ]; then
    echo "FAIL: refusing to overwrite existing artifact path: $ARTIFACT_DIR" >&2
    exit 2
fi
if [ ! -d "$(dirname "$ARTIFACT_DIR")" ]; then
    echo "FAIL: artifact parent directory does not exist: $(dirname "$ARTIFACT_DIR")" >&2
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
for required_command in flock ip iperf3 nc openssl ping python3 sha256sum tc timeout; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fatal "required command is not available: $required_command"
done
mkdir "$ARTIFACT_DIR" || fatal "could not create artifact directory: $ARTIFACT_DIR"
{
    printf 'binary_sha256=%s\n' "$(sha256sum "$B" | awk '{print $1}')"
    printf 'uniform_ping_contract=%s\n' "${UNIFORM_PING_SCENARIOS[*]}"
    printf 'uniform_iperf_contract=%s\n' "${UNIFORM_IPERF_SCENARIOS[*]}"
    printf 'ping_count=%s\n' "$PING_COUNT"
    printf 'ping_interval_seconds=%s\n' "$PING_INTERVAL"
} > "$ARTIFACT_DIR/run-manifest.txt" || fatal "could not create uniform evidence manifest"
printf 'kind\tscenario\tmeasurement\tlimit\tstatus\n' > "$ARTIFACT_DIR/results.tsv" \
    || fatal "could not create uniform evidence results"
RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-fec-netns.XXXXXX)" || fatal "could not create runtime directory"
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
    IPERF_LOG="$CURRENT_SCENARIO_DIR/iperf-server.log"
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
    for ns in ns-srv ns-cli; do
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.default.rp_filter=0 2>/dev/null
    done
}

apply_loss() {
    local loss_pct="$1"
    if [ "$loss_pct" = "0" ]; then
        return
    fi
    # Apply tc-netem loss on the CLIENT side (inbound to server = outbound from client)
    # This simulates loss on the path from client to server
    if ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss "${loss_pct}%"; then
        QDISC_CREATED=1
    else
        fatal "could not apply ${loss_pct}% netem loss"
    fi
}

remove_loss() {
    remove_qdisc || fatal "could not remove owned netem loss"
}

start_server() {
    ip netns exec ns-srv "$B" server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket "$ADMIN_SOCKET" \
        --qkey-store "$QKEY_STORE" \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
        --no-drop-privileges -v \
        > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 3
}

start_client() {
    local qkey="$1"
    ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
        --qkey "$qkey" --ca-file "$CA" --verify-peer \
        --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 --no-utls -v \
        > "$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
    sleep 4

    # Ensure TUN up + ip + route in each netns
    ip netns exec ns-srv ip addr add 10.0.1.1/24 dev qtun0 2>/dev/null
    ip netns exec ns-srv ip link set qtun0 up 2>/dev/null
    ip netns exec ns-cli ip addr add 10.0.1.2/24 dev qtun0 2>/dev/null
    ip netns exec ns-cli ip link set qtun0 up 2>/dev/null
    sleep 2
}

get_qkey() {
    echo '{"cmd":"qkey"}' | nc -U "$ADMIN_SOCKET" 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null
}

run_loss_level() {
    local loss_pct="$1"
    local max_loss="$2"
    echo ""
    echo "=========================================="
    echo "  FEC E2E Test: ${loss_pct}% tc-netem loss"
    echo "=========================================="

    cleanup_owned_resources || fatal "could not clean the previous loss scenario"
    prepare_scenario_runtime "loss-${loss_pct}"
    setup_netns

    start_server
    local qkey
    qkey=$(get_qkey)
    if [ -z "$qkey" ]; then
        echo "FAIL: could not get qkey from server"
        FAIL=$((FAIL + 1))
        record_result qkey "$loss_pct" missing present fail
        preserve_failure_if_requested
        return
    fi
    start_client "$qkey"

    # Verify handshake
    local cli_complete srv_complete
    cli_complete=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli_complete=${cli_complete:-0}
    srv_complete=${srv_complete:-0}
    if [ "$cli_complete" = "0" ] || [ "$srv_complete" = "0" ]; then
        echo "FAIL: TLS handshake not complete (cli=$cli_complete srv=$srv_complete)"
        FAIL=$((FAIL + 1))
        record_result handshake "$loss_pct" "client=${cli_complete},server=${srv_complete}" positive fail
        preserve_failure_if_requested
        return
    fi
    echo "OK: TLS handshake complete on both sides"
    record_result handshake "$loss_pct" "client=${cli_complete},server=${srv_complete}" positive pass

    # Apply loss AFTER handshake (so handshake succeeds)
    apply_loss "$loss_pct"
    if [ "$loss_pct" != "0" ]; then
        echo "Applied tc-netem loss: ${loss_pct}%"
    fi

    # Ping through tunnel (fast interval to fill FEC windows quickly)
    echo "Pinging through tunnel (${PING_COUNT} pings @ ${PING_INTERVAL}s interval, ${loss_pct}% loss)..."
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 3 -I qtun0 10.0.1.1 2>&1)
    printf '%s\n' "$ping_output" > "$ARTIFACT_DIR/ping-loss-${loss_pct}.txt" \
        || fatal "could not preserve ${loss_pct}% ping evidence"
    echo "$ping_output" | tail -3

    # Extract packet loss percentage (handle decimals like "3.33%")
    local ping_loss
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    echo "Ping loss through tunnel: ${ping_loss}%"

    if [ "$ping_loss" -le "$max_loss" ]; then
        echo "PASS: ${loss_pct}% netem loss -> ${ping_loss}% tunnel loss (threshold: ${max_loss}%)"
        PASS=$((PASS + 1))
        record_result ping "$loss_pct" "$ping_loss" "$max_loss" pass
    else
        echo "FAIL: ${loss_pct}% netem loss -> ${ping_loss}% tunnel loss (threshold: ${max_loss}%)"
        FAIL=$((FAIL + 1))
        record_result ping "$loss_pct" "$ping_loss" "$max_loss" fail
    fi

    # Check FEC mode telemetry
    echo "=== FEC telemetry ==="
    echo "srv FEC: $(grep -i 'FEC_MODE\|fec.*mode' "$SERVER_LOG" | tail -3)"
    echo "cli FEC: $(grep -i 'FEC_MODE\|fec.*mode' "$CLIENT_LOG" | tail -3)"

    check_runtime_logs "ping-loss-${loss_pct}" || true

    preserve_failure_if_requested
    remove_loss
}

# --- iperf3 bulk throughput test ---
run_iperf_test() {
    local loss_pct="$1"

    echo ""
    echo "=========================================="
    echo "  FEC iperf3 Bulk Test: ${loss_pct}% loss"
    echo "=========================================="

    cleanup_owned_resources || fatal "could not clean the previous iperf scenario"
    prepare_scenario_runtime "iperf-${loss_pct}"
    setup_netns

    start_server
    local qkey
    qkey=$(get_qkey)
    if [ -z "$qkey" ]; then
        echo "FAIL: could not get qkey"
        FAIL=$((FAIL + 1))
        record_result qkey "iperf-${loss_pct}" missing present fail
        preserve_failure_if_requested
        return
    fi
    start_client "$qkey"

    local cli_complete srv_complete
    cli_complete=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli_complete=${cli_complete:-0}
    srv_complete=${srv_complete:-0}
    if [ "$cli_complete" = "0" ] || [ "$srv_complete" = "0" ]; then
        echo "FAIL: iperf TLS handshake not complete (cli=$cli_complete srv=$srv_complete)"
        FAIL=$((FAIL + 1))
        record_result handshake "iperf-${loss_pct}" "client=${cli_complete},server=${srv_complete}" positive fail
        preserve_failure_if_requested
        return
    fi
    record_result handshake "iperf-${loss_pct}" "client=${cli_complete},server=${srv_complete}" positive pass

    # Start iperf3 server on ns-srv TUN IP
    ip netns exec ns-srv iperf3 -s -B 10.0.1.1 -p 5201 --one-off >"$IPERF_LOG" 2>&1 &
    IPERF_SERVER_PID=$!
    sleep 1

    apply_loss "$loss_pct"

    # Run a bounded client and prove the receiver, not just sender-formatted
    # output, received useful data continuously.
    local iperf_json="$ARTIFACT_DIR/iperf-loss-${loss_pct}.json"
    if ! ip netns exec ns-cli timeout 20 iperf3 -c 10.0.1.1 -p 5201 -t 10 -b 1M -J > "$iperf_json"; then
        echo "FAIL: ${loss_pct}% loss iperf3 client did not terminate successfully"
        FAIL=$((FAIL + 1))
        record_result iperf "$loss_pct" client-exit zero fail
        check_runtime_logs "iperf-loss-${loss_pct}" || true
        stop_owned_process "$IPERF_SERVER_PID"
        IPERF_SERVER_PID=""
        preserve_failure_if_requested
        remove_loss
        return
    fi

    if ! wait "$IPERF_SERVER_PID"; then
        echo "FAIL: ${loss_pct}% loss iperf3 receiver did not terminate successfully"
        FAIL=$((FAIL + 1))
        record_result iperf "$loss_pct" receiver-exit zero fail
        check_runtime_logs "iperf-loss-${loss_pct}" || true
        IPERF_SERVER_PID=""
        preserve_failure_if_requested
        remove_loss
        return
    fi
    IPERF_SERVER_PID=""

    local measurement
    if ! measurement=$(python3 -c \
        'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); sender=data["end"]["sum_sent"]; receiver=data["end"]["sum_received"]; intervals=[sample["sum"] for sample in data["intervals"]]; assert sender["bytes"] > 0 and sender["bits_per_second"] > 0, sender; assert receiver["bytes"] > 0 and receiver["bits_per_second"] > 0, receiver; assert intervals and all(item["bytes"] > 0 and item["bits_per_second"] > 0 for item in intervals), intervals; print("{:.6f} {}".format(receiver["bits_per_second"] / 1_000_000, sender.get("retransmits", 0)))' \
        "$iperf_json"); then
        echo "FAIL: ${loss_pct}% loss iperf3 lacks positive receiver throughput in every interval"
        FAIL=$((FAIL + 1))
        record_result iperf "$loss_pct" invalid positive fail
        check_runtime_logs "iperf-loss-${loss_pct}" || true
        preserve_failure_if_requested
        remove_loss
        return
    fi

    local throughput retransmits
    read -r throughput retransmits <<< "$measurement"
    echo "Receiver throughput: ${throughput} Mbits/sec, sender retransmits: ${retransmits}"

    echo "PASS: ${loss_pct}% loss iperf3 receiver delivered ${throughput} Mbits/sec"
    PASS=$((PASS + 1))
    record_result iperf "$loss_pct" "$throughput" positive pass
    check_runtime_logs "iperf-loss-${loss_pct}" || true

    preserve_failure_if_requested
    remove_loss
}

# --- Main ---
echo "=== FEC E2E Test Suite (TODO-423) ==="
echo "Uniform ping contract: ${UNIFORM_PING_SCENARIOS[*]} (netem-loss:max-tunnel-loss)"
echo "Uniform iperf contract: ${UNIFORM_IPERF_SCENARIOS[*]} (netem loss, positive receiver intervals)"
echo "Ping count per level: ${PING_COUNT}"

for scenario in "${UNIFORM_PING_SCENARIOS[@]}"; do
    IFS=':' read -r loss max_loss <<< "$scenario"
    run_loss_level "$loss" "$max_loss"
done

for loss in "${UNIFORM_IPERF_SCENARIOS[@]}"; do
    run_iperf_test "$loss"
done

cleanup_owned_resources || fatal "could not clean final owned resources"

echo ""
echo "=========================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "  Evidence: ${ARTIFACT_DIR}"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
remove_runtime_dir || fatal "could not remove isolated runtime directory"
trap - EXIT INT TERM
exit 0
