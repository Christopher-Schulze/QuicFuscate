#!/usr/bin/env bash
# E2E FEC burst loss test through real QUIC transport with tc-netem.
#
# Tests FEC recovery under bursty loss patterns (correlated loss) which are
# more realistic than uniform random loss. tc-netem supports loss correlation
# to simulate burst loss.
#
# Executable acceptance (TODO-423):
#   - BURST_SCENARIOS is the single source for executed loss/correlation
#     profiles and their statistical bounds.
#   - TLS handshakes complete on both endpoints.
#   - No panics.
#
# Requirements: root, Linux, iproute2, tc-netem, openssl, python3, nc.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="$PROJECT_ROOT/config/local/ca.crt"
CA_KEY="$PROJECT_ROOT/config/local/ca.key"

PING_COUNT="${PING_COUNT:-100}"
PING_INTERVAL="${PING_INTERVAL:-0.1}"
BURST_REPETITIONS="${QF_BURST_REPETITIONS:-3}"
BURST_SCENARIOS=(
    "mild:10:25:5:10"
    "heavy:20:50:10:15"
)
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
ARTIFACT_DIR="${QF_E2E_ARTIFACT_DIR:-/tmp/quicfuscate-fec-burst-evidence-$$}"
RUNTIME_FAILURE_PATTERN='panic|Crypto error: crypto failure|AEAD limit reached|Key update error|heartbeat timeout|InternalError|TUN packet send failed'
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
ADMIN_SOCKET=""
QKEY_STORE=""
CERT=""
KEY=""
LAST_PING_LOSS=""

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
        /tmp/quicfuscate-fec-burst.*)
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

check_runtime_logs() {
    local scenario="$1"
    local matches="$ARTIFACT_DIR/runtime-errors-${scenario}.txt"
    if grep -EHi "$RUNTIME_FAILURE_PATTERN" "$SERVER_LOG" "$CLIENT_LOG" > "$matches" 2>/dev/null; then
        echo "FAIL: ${scenario} logs contain a panic, decryption, heartbeat, internal, or TUN-send failure"
        FAIL=$((FAIL + 1))
        printf '%s\tfailure\tdetected\n' "$scenario" >> "$ARTIFACT_DIR/runtime.tsv" \
            || fatal "could not append ${scenario} runtime failure evidence"
        return 1
    fi
    rm -f -- "$matches"
    printf '%s\tpass\t0\n' "$scenario" >> "$ARTIFACT_DIR/runtime.tsv" \
        || fatal "could not append ${scenario} runtime evidence"
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
case "$BURST_REPETITIONS" in
    ''|*[!0-9]*) echo "FAIL: QF_BURST_REPETITIONS must be an integer" >&2; exit 2 ;;
esac
if [ "$BURST_REPETITIONS" -lt 3 ]; then
    echo "FAIL: QF_BURST_REPETITIONS must be at least 3" >&2
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
for required_command in flock ip nc openssl ping python3 seq sha256sum tc; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fatal "required command is not available: $required_command"
done
mkdir "$ARTIFACT_DIR" || fatal "could not create artifact directory: $ARTIFACT_DIR"
{
    printf 'binary_sha256=%s\n' "$(sha256sum "$B" | awk '{print $1}')"
    printf 'burst_contract=%s\n' "${BURST_SCENARIOS[*]}"
    printf 'burst_repetitions=%s\n' "$BURST_REPETITIONS"
    printf 'ping_count=%s\n' "$PING_COUNT"
    printf 'ping_interval_seconds=%s\n' "$PING_INTERVAL"
} > "$ARTIFACT_DIR/run-manifest.txt" || fatal "could not create burst evidence manifest"
printf 'profile\ttrial\tnetem_loss_percent\tcorrelation_percent\ttunnel_loss_percent\tmedian_limit_percent\tsample_limit_percent\n' \
    > "$ARTIFACT_DIR/results.tsv" || fatal "could not create burst evidence results"
printf 'scenario\tstatus\tdetail\n' > "$ARTIFACT_DIR/runtime.tsv" \
    || fatal "could not create burst runtime evidence"
RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-fec-burst.XXXXXX)" || fatal "could not create runtime directory"
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
    for ns in ns-srv ns-cli; do
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.default.rp_filter=0 2>/dev/null
    done
}

run_burst_trial() {
    local loss_pct="$1"
    local correlation="$2"
    local label="$3"
    local trial="$4"

    echo ""
    echo "=========================================="
    echo "  FEC Burst Loss: ${label}, trial ${trial}/${BURST_REPETITIONS}"
    echo "=========================================="

    cleanup_owned_resources || fatal "could not clean the previous burst scenario"
    prepare_scenario_runtime "burst-${loss_pct}-${correlation}-trial-${trial}"
    setup_netns

    ip netns exec ns-srv "$B" server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket "$ADMIN_SOCKET" \
        --qkey-store "$QKEY_STORE" \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
        --no-drop-privileges -v \
        > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 3

    local qkey
    qkey=$(echo '{"cmd":"qkey"}' | nc -U "$ADMIN_SOCKET" 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)
    if [ -z "$qkey" ]; then
        echo "FAIL: could not get qkey from server"
        FAIL=$((FAIL + 1))
        printf '%s\tfailure\tqkey-missing\n' "${label// /-}-trial-${trial}" \
            >> "$ARTIFACT_DIR/runtime.tsv" \
            || fatal "could not append missing-QKey evidence"
        preserve_failure_if_requested
        return
    fi

    # Start client
    ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
        --qkey "$qkey" --ca-file "$CA" --verify-peer --disable-doh \
        --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 --no-utls -v \
        > "$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
    sleep 4

    ip netns exec ns-srv ip addr add 10.0.1.1/24 dev qtun0 2>/dev/null
    ip netns exec ns-srv ip link set qtun0 up 2>/dev/null
    ip netns exec ns-cli ip addr add 10.0.1.2/24 dev qtun0 2>/dev/null
    ip netns exec ns-cli ip link set qtun0 up 2>/dev/null
    sleep 2

    local cli_complete srv_complete
    cli_complete=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv_complete=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli_complete=${cli_complete:-0}
    srv_complete=${srv_complete:-0}
    if [ "$cli_complete" -eq 0 ] || [ "$srv_complete" -eq 0 ]; then
        echo "FAIL: TLS handshake not complete (cli=$cli_complete srv=$srv_complete)"
        FAIL=$((FAIL + 1))
        printf '%s\tfailure\thandshake-client-%s-server-%s\n' \
            "${label// /-}-trial-${trial}" "$cli_complete" "$srv_complete" \
            >> "$ARTIFACT_DIR/runtime.tsv" \
            || fatal "could not append handshake failure evidence"
        preserve_failure_if_requested
        return
    fi
    printf '%s\tpass\thandshake-client-%s-server-%s\n' \
        "${label// /-}-trial-${trial}" "$cli_complete" "$srv_complete" \
        >> "$ARTIFACT_DIR/runtime.tsv" \
        || fatal "could not append handshake evidence"

    # Apply burst loss AFTER handshake
    if ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss "${loss_pct}%" "${correlation}%"; then
        QDISC_CREATED=1
    else
        fatal "could not apply correlated netem loss"
    fi
    echo "Applied: ${loss_pct}% loss with ${correlation}% correlation"

    echo "Pinging through tunnel (${PING_COUNT} pings @ ${PING_INTERVAL}s interval)..."
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 3 -I qtun0 10.0.1.1 2>&1)
    printf '%s\n' "$ping_output" \
        > "$ARTIFACT_DIR/ping-${label// /-}-trial-${trial}.txt" \
        || fatal "could not preserve ${label} trial ${trial} ping evidence"
    echo "$ping_output" | tail -3

    local ping_loss
    # Extract integer packet loss percentage (handle decimals like "3.33%")
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    echo "Tunnel loss: ${ping_loss}%"
    LAST_PING_LOSS="$ping_loss"

    check_runtime_logs "${label// /-}-trial-${trial}" || true

    preserve_failure_if_requested
    remove_qdisc || fatal "could not remove correlated netem loss"
}

run_burst_scenario() {
    local loss_pct="$1"
    local correlation="$2"
    local label="$3"
    local median_limit="$4"
    local sample_limit="$5"
    local trial
    local -a samples=()

    for trial in $(seq 1 "$BURST_REPETITIONS"); do
        LAST_PING_LOSS=""
        run_burst_trial "$loss_pct" "$correlation" "$label" "$trial"
        if [ -z "$LAST_PING_LOSS" ]; then
            echo "FAIL: ${label} trial ${trial} produced no packet-loss measurement"
            FAIL=$((FAIL + 1))
            continue
        fi
        samples+=("$LAST_PING_LOSS")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$label" "$trial" "$loss_pct" "$correlation" "$LAST_PING_LOSS" \
            "$median_limit" "$sample_limit" >> "$ARTIFACT_DIR/results.tsv" \
            || fatal "could not append ${label} trial ${trial} evidence"
    done

    if [ "${#samples[@]}" -ne "$BURST_REPETITIONS" ]; then
        echo "FAIL: ${label} completed ${#samples[@]}/${BURST_REPETITIONS} measurements"
        return
    fi

    local aggregate
    if ! aggregate=$(python3 -c \
        'import statistics,sys; median_limit=int(sys.argv[1]); sample_limit=int(sys.argv[2]); samples=[int(value) for value in sys.argv[3:]]; median=statistics.median(samples); maximum=max(samples); print(f"samples={samples}; median={median:g}%; maximum={maximum}%"); assert median <= median_limit, (samples, median, median_limit); assert maximum <= sample_limit, (samples, maximum, sample_limit)' \
        "$median_limit" "$sample_limit" "${samples[@]}"); then
        echo "FAIL: ${label} statistical gate failed (median <=${median_limit}%, every sample <=${sample_limit}%)"
        FAIL=$((FAIL + 1))
        return
    fi
    echo "PASS: ${label} ${aggregate}"
    printf '%s\t%s\n' "$label" "$aggregate" >> "$ARTIFACT_DIR/summary.tsv" \
        || fatal "could not append ${label} aggregate evidence"
    PASS=$((PASS + 1))
}

# --- Main ---
echo "=== FEC Burst Loss E2E Test Suite (TODO-423) ==="
echo "Burst contract: ${BURST_SCENARIOS[*]} (label:loss:correlation:median:max-sample)"
printf 'profile\taggregate\n' > "$ARTIFACT_DIR/summary.tsv" \
    || fatal "could not create burst aggregate evidence"

for scenario in "${BURST_SCENARIOS[@]}"; do
    IFS=':' read -r label loss_pct correlation median_limit sample_limit <<< "$scenario"
    run_burst_scenario "$loss_pct" "$correlation" "$label burst" "$median_limit" "$sample_limit"
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
