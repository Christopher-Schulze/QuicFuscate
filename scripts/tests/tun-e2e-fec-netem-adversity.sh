#!/usr/bin/env bash
# FEC liveness under network adversity - tc-netem test suite (TODO-425).
#
# Tests authenticated TUN liveness under these degradation patterns:
#   1. Loss sweep (0-50%)
#   2. Jitter sweep (0-500ms)
#   3. Bandwidth limitation (1-100Mbit)
#   4. RTT variation (1-300ms plus 5% loss)
#   5. Combined adversity (mobile network simulation)
#   6. Adversity recovery (clean → loss → clean transitions)
#
# Acceptance criteria:
#   - Each scenario establishes the authenticated tunnel and enforces its
#     scenario-specific ping-loss limit.
#   - Every scenario fails on a detected runtime panic.
#   - The recovery path requires clean-link and post-loss liveness.
#
# This harness deliberately does not claim throughput, FEC overhead, mode
# stability, retransmission latency, or a timed stability interval. Those
# quantitative contracts belong to the specialized acceptance work in TODO-557.
#
# Requirements: root, Linux, iproute2, tc-netem, openssl, python3, nc.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
CA="$PROJECT_ROOT/config/local/ca.crt"
CA_KEY="$PROJECT_ROOT/config/local/ca.key"

ADVERSITY_PING_COUNT=50
ADVERSITY_PING_INTERVAL=0.1
LOSS_SCENARIOS=(
    "0:15"
    "1:16"
    "5:20"
    "10:25"
    "25:40"
    "50:65"
)
JITTER_SCENARIOS=(
    "0:50:25:10"
    "10:50:25:10"
    "50:50:25:10"
    "100:50:25:10"
    "200:50:25:10"
    "500:50:25:10"
)
BANDWIDTH_SCENARIOS=(
    "100Mbit:32kbit:400ms:5"
    "50Mbit:32kbit:400ms:5"
    "10Mbit:32kbit:400ms:5"
    "5Mbit:32kbit:400ms:5"
    "1Mbit:32kbit:400ms:5"
)
RTT_SCENARIOS=(
    "1:5:20"
    "10:5:20"
    "50:5:20"
    "100:5:20"
    "200:5:20"
    "300:5:20"
)
COMBINED_SCENARIO="100:10:25:5:10Mbit:32kbit:400ms:25"
RECOVERY_SCENARIO="20:5:10:2:3"
ADVERSITY_SUITE="${QF_ADVERSITY_SUITE:-all}"
TELEMETRY_PORT="${QF_FEC_TELEMETRY_PORT:-9898}"
EVIDENCE_DIR="${QF_E2E_ARTIFACT_DIR:-}"
KEEP_ON_FAIL="${QF_E2E_KEEP_ON_FAIL:-0}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
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
TELEMETRY_FILES=()
EVIDENCE_PRESERVED=0
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
        /tmp/quicfuscate-fec-adversity.*)
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
    if [ "$status" -ne 0 ] && [ -n "$EVIDENCE_DIR" ] && [ "${#TELEMETRY_FILES[@]}" -gt 0 ]; then
        preserve_telemetry_evidence || true
    fi
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
case "$ADVERSITY_SUITE" in
    all|loss|jitter|bandwidth|rtt|combined|recovery) ;;
    *)
        echo "FAIL: QF_ADVERSITY_SUITE must select all, loss, jitter, bandwidth, rtt, combined, or recovery" >&2
        exit 2
        ;;
esac
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
# Load required kernel modules for tc-netem.
modprobe sch_netem 2>/dev/null || true
modprobe sch_tbf 2>/dev/null || true

RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-fec-adversity.XXXXXX)" || fatal "could not create runtime directory"
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

start_tunnel() {
    ip netns exec ns-srv env QUICFUSCATE_METRICS_ADDR="127.0.0.1:${TELEMETRY_PORT}" \
        "$B" --telemetry server --cert "$CERT" --key "$KEY" \
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
        fatal "could not get qkey from server"
    fi

    ip netns exec ns-cli env QUICFUSCATE_METRICS_ADDR="127.0.0.1:${TELEMETRY_PORT}" \
        "$B" --telemetry client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
        --qkey "$qkey" --ca-file "$CA" --verify-peer \
        --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 --no-utls -v \
        > "$CLIENT_LOG" 2>&1 &
    CLIENT_PID=$!
    sleep 4

    ip netns exec ns-srv ip addr add 10.0.1.1/24 dev qtun0 2>/dev/null
    ip netns exec ns-srv ip link set qtun0 up 2>/dev/null
    ip netns exec ns-cli ip addr add 10.0.1.2/24 dev qtun0 2>/dev/null
    ip netns exec ns-cli ip link set qtun0 up 2>/dev/null
    sleep 2
}

apply_qdisc() {
    local qdisc="$1"
    if [ -n "$qdisc" ]; then
        # shellcheck disable=SC2086
        if ip netns exec ns-cli tc qdisc add dev veth-cli root $qdisc; then
            QDISC_CREATED=1
        else
            fatal "could not apply qdisc: $qdisc"
        fi
    fi
}

ping_through_tunnel() {
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$ADVERSITY_PING_COUNT" -i "$ADVERSITY_PING_INTERVAL" -W 5 -I qtun0 10.0.1.1 2>&1)
    local ping_loss
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    # Extract avg RTT (second value in "min/avg/max/mdev = X/Y/Z/W")
    local ping_rtt
    ping_rtt=$(echo "$ping_output" | grep 'rtt min' | sed 's|.*/\([0-9.]*\)/.*|\1|' || echo "0")
    echo "${ping_loss}:${ping_rtt}"
}

check_handshake() {
    local cli srv
    cli=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli=${cli:-0}
    srv=${srv:-0}
    [ "$cli" -gt 0 ] && [ "$srv" -gt 0 ]
}

check_panics() {
    if grep -q 'panic' "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
        return 1
    fi
    return 0
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

capture_telemetry() {
    local scenario="$1"
    SERVER_TELEMETRY="$CURRENT_SCENARIO_DIR/server-${scenario}.telemetry"
    CLIENT_TELEMETRY="$CURRENT_SCENARIO_DIR/client-${scenario}.telemetry"
    fetch_telemetry ns-srv "$SERVER_TELEMETRY" \
        || fatal "server telemetry endpoint unavailable during ${scenario}"
    fetch_telemetry ns-cli "$CLIENT_TELEMETRY" \
        || fatal "client telemetry endpoint unavailable during ${scenario}"

    local file active observed lost repairs switches
    for file in "$SERVER_TELEMETRY" "$CLIENT_TELEMETRY"; do
        active=$(metric_value "$file" "quicfuscate_fec_active_connections_total") \
            || fatal "missing active FEC connection metric during ${scenario}"
        observed=$(metric_value "$file" "quicfuscate_fec_observed_packets_total") \
            || fatal "missing observed FEC packet metric during ${scenario}"
        lost=$(metric_value "$file" "quicfuscate_fec_observed_lost_packets_total") \
            || fatal "missing observed FEC loss metric during ${scenario}"
        repairs=$(metric_value "$file" "quicfuscate_fec_repair_packets_sent_total") \
            || fatal "missing FEC repair metric during ${scenario}"
        switches=$(metric_value "$file" "quicfuscate_fec_mode_switches_total") \
            || fatal "missing FEC mode-switch metric during ${scenario}"
        [ "$active" -ge 1 ] || fatal "telemetry has no active FEC connection during ${scenario}"
        printf 'FEC telemetry %s: active=%s observed=%s lost=%s repairs=%s switches=%s\n' \
            "$scenario" "$active" "$observed" "$lost" "$repairs" "$switches"
    done
    TELEMETRY_FILES+=("$SERVER_TELEMETRY" "$CLIENT_TELEMETRY")
}

preserve_telemetry_evidence() {
    if [ -z "$EVIDENCE_DIR" ]; then
        return
    fi
    if [ "$EVIDENCE_PRESERVED" = "1" ]; then
        return
    fi
    if [ "${#TELEMETRY_FILES[@]}" -eq 0 ]; then
        echo "FAIL: no telemetry evidence captured for requested artifact directory" >&2
        return 1
    fi
    mkdir "$EVIDENCE_DIR" || {
        echo "FAIL: could not create evidence directory: $EVIDENCE_DIR" >&2
        return 1
    }
    cp -- "${TELEMETRY_FILES[@]}" "$EVIDENCE_DIR/" \
        || {
            echo "FAIL: could not preserve telemetry evidence" >&2
            return 1
        }
    {
        printf 'suite=%s\n' "$ADVERSITY_SUITE"
        printf 'binary_sha256=%s\n' "$(sha256sum "$B" | awk '{print $1}')"
        printf 'ping_count=%s\n' "$ADVERSITY_PING_COUNT"
        printf 'ping_interval_seconds=%s\n' "$ADVERSITY_PING_INTERVAL"
        printf 'loss_contract=%s\n' "${LOSS_SCENARIOS[*]}"
        printf 'jitter_contract=%s\n' "${JITTER_SCENARIOS[*]}"
        printf 'bandwidth_contract=%s\n' "${BANDWIDTH_SCENARIOS[*]}"
        printf 'rtt_contract=%s\n' "${RTT_SCENARIOS[*]}"
        printf 'combined_contract=%s\n' "$COMBINED_SCENARIO"
        printf 'recovery_contract=%s\n' "$RECOVERY_SCENARIO"
    } > "$EVIDENCE_DIR/run-manifest.txt" \
        || {
            echo "FAIL: could not write telemetry evidence manifest" >&2
            return 1
        }
    EVIDENCE_PRESERVED=1
    echo "Evidence: $EVIDENCE_DIR"
}

# ---------------------------------------------------------------------------
# 1. Loss sweep
# ---------------------------------------------------------------------------
test_loss_sweep() {
    echo ""
    echo "=========================================="
    echo "  1. Loss Sweep"
    echo "=========================================="
    echo "loss% | tunnel_loss% | rtt_ms | status"

    for scenario in "${LOSS_SCENARIOS[@]}"; do
        IFS=':' read -r loss max_loss <<< "$scenario"
        cleanup_owned_resources || fatal "could not clean the previous loss scenario"
        prepare_scenario_runtime "loss-${loss}"
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${loss}% | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            preserve_failure_if_requested
            continue
        fi
        if [ "$loss" != "0" ]; then
            apply_qdisc "netem loss ${loss}%"
        fi
        local result
        result=$(ping_through_tunnel)
        capture_telemetry "loss-${loss}"
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        if [ "$tunnel_loss" -le "$max_loss" ]; then
            echo "${loss}% | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${loss}% | ${tunnel_loss}% | ${rtt} | FAIL (threshold ${max_loss}%)"
            FAIL=$((FAIL + 1))
        fi
        if ! check_panics; then
            echo "${loss}% | FAIL (panic)"
            FAIL=$((FAIL + 1))
        fi
        preserve_failure_if_requested
        remove_qdisc || fatal "could not remove loss-sweep qdisc"
    done
}

# ---------------------------------------------------------------------------
# 2. Jitter sweep
# ---------------------------------------------------------------------------
test_jitter_sweep() {
    echo ""
    echo "=========================================="
    echo "  2. Jitter Sweep"
    echo "=========================================="
    echo "jitter_ms | tunnel_loss% | rtt_ms | status"

    for scenario in "${JITTER_SCENARIOS[@]}"; do
        IFS=':' read -r jitter base_delay correlation max_loss <<< "$scenario"
        cleanup_owned_resources || fatal "could not clean the previous jitter scenario"
        prepare_scenario_runtime "jitter-${jitter}"
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${jitter}ms | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            preserve_failure_if_requested
            continue
        fi
        if [ "$jitter" != "0" ]; then
            apply_qdisc "netem delay ${base_delay}ms ${jitter}ms ${correlation}%"
        fi
        local result
        result=$(ping_through_tunnel)
        capture_telemetry "jitter-${jitter}"
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        if [ "$tunnel_loss" -le "$max_loss" ]; then
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | FAIL (threshold ${max_loss}%)"
            FAIL=$((FAIL + 1))
        fi
        if ! check_panics; then
            echo "${jitter}ms | FAIL (panic)"
            FAIL=$((FAIL + 1))
        fi
        preserve_failure_if_requested
        remove_qdisc || fatal "could not remove jitter-sweep qdisc"
    done
}

# ---------------------------------------------------------------------------
# 3. Bandwidth limitation
# ---------------------------------------------------------------------------
test_bandwidth() {
    echo ""
    echo "=========================================="
    echo "  3. Bandwidth Limitation"
    echo "=========================================="
    echo "bandwidth | tunnel_loss% | rtt_ms | status"

    for scenario in "${BANDWIDTH_SCENARIOS[@]}"; do
        IFS=':' read -r bw burst latency max_loss <<< "$scenario"
        cleanup_owned_resources || fatal "could not clean the previous bandwidth scenario"
        prepare_scenario_runtime "bandwidth-${bw}"
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${bw} | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            preserve_failure_if_requested
            continue
        fi
        apply_qdisc "tbf rate ${bw} burst ${burst} latency ${latency}"
        local result
        result=$(ping_through_tunnel)
        capture_telemetry "bandwidth-${bw}"
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        if [ "$tunnel_loss" -le "$max_loss" ]; then
            echo "${bw} | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${bw} | ${tunnel_loss}% | ${rtt} | FAIL (threshold ${max_loss}%)"
            FAIL=$((FAIL + 1))
        fi
        if ! check_panics; then
            echo "${bw} | FAIL (panic)"
            FAIL=$((FAIL + 1))
        fi
        preserve_failure_if_requested
        remove_qdisc || fatal "could not remove bandwidth qdisc"
    done
}

# ---------------------------------------------------------------------------
# 4. RTT variation
# ---------------------------------------------------------------------------
test_rtt_variation() {
    echo ""
    echo "=========================================="
    echo "  4. RTT Variation"
    echo "=========================================="
    echo "rtt_ms | tunnel_loss% | measured_rtt_ms | status"

    for scenario in "${RTT_SCENARIOS[@]}"; do
        IFS=':' read -r rtt netem_loss max_loss <<< "$scenario"
        cleanup_owned_resources || fatal "could not clean the previous RTT scenario"
        prepare_scenario_runtime "rtt-${rtt}"
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${rtt}ms | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            preserve_failure_if_requested
            continue
        fi
        apply_qdisc "netem delay ${rtt}ms loss ${netem_loss}%"
        local result
        result=$(ping_through_tunnel)
        capture_telemetry "rtt-${rtt}"
        local tunnel_loss measured_rtt
        tunnel_loss=${result%%:*}
        measured_rtt=${result##*:}

        if [ "$tunnel_loss" -le "$max_loss" ]; then
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | FAIL (threshold ${max_loss}%)"
            FAIL=$((FAIL + 1))
        fi
        if ! check_panics; then
            echo "${rtt}ms | FAIL (panic)"
            FAIL=$((FAIL + 1))
        fi
        preserve_failure_if_requested
        remove_qdisc || fatal "could not remove RTT qdisc"
    done
}

# ---------------------------------------------------------------------------
# 5. Combined adversity
# ---------------------------------------------------------------------------
test_combined_adversity() {
    echo ""
    echo "=========================================="
    echo "  5. Combined Adversity"
    echo "=========================================="
    local delay_ms jitter_ms correlation netem_loss bandwidth burst latency max_loss
    IFS=':' read -r delay_ms jitter_ms correlation netem_loss bandwidth burst latency max_loss <<< "$COMBINED_SCENARIO"
    echo "  ${delay_ms}ms RTT + ${jitter_ms}ms jitter + ${netem_loss}% loss + ${bandwidth}"

    cleanup_owned_resources || fatal "could not clean the previous combined-adversity scenario"
    prepare_scenario_runtime "combined"
    setup_netns
    start_tunnel
    if ! check_handshake; then
        echo "FAIL: handshake failed"
        FAIL=$((FAIL + 1))
        preserve_failure_if_requested
        return
    fi

    # Apply combined qdisc: netem (delay+jitter+loss) then tbf (bandwidth)
    if ip netns exec ns-cli tc qdisc add dev veth-cli root handle 1: netem delay "${delay_ms}ms" "${jitter_ms}ms" "${correlation}%" loss "${netem_loss}%"; then
        QDISC_CREATED=1
    else
        fatal "could not apply combined root netem qdisc"
    fi
    ip netns exec ns-cli tc qdisc add dev veth-cli parent 1: handle 2: tbf rate "$bandwidth" burst "$burst" latency "$latency" \
        || fatal "could not apply combined child tbf qdisc"

    local result
    result=$(ping_through_tunnel)
    capture_telemetry "combined"
    local tunnel_loss rtt
    tunnel_loss=${result%%:*}
    rtt=${result##*:}

    if [ "$tunnel_loss" -le "$max_loss" ]; then
        echo "PASS: ${tunnel_loss}% tunnel loss, ${rtt} rtt"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${tunnel_loss}% tunnel loss (threshold ${max_loss}%)"
        FAIL=$((FAIL + 1))
    fi

    if ! check_panics; then
        echo "FAIL: panic detected"
        FAIL=$((FAIL + 1))
    fi
    preserve_failure_if_requested
    remove_qdisc || fatal "could not remove combined-adversity qdisc"
}

# ---------------------------------------------------------------------------
# 6. Adversity recovery
# ---------------------------------------------------------------------------
test_adversity_recovery() {
    echo ""
    echo "=========================================="
    echo "  6. Adversity Recovery"
    echo "=========================================="

    cleanup_owned_resources || fatal "could not clean the previous recovery scenario"
    prepare_scenario_runtime "recovery"
    setup_netns
    start_tunnel
    if ! check_handshake; then
        echo "FAIL: handshake failed"
        FAIL=$((FAIL + 1))
        preserve_failure_if_requested
        return
    fi

    local netem_loss clean_max_loss recovery_max_loss loss_settle_seconds recovery_settle_seconds
    IFS=':' read -r netem_loss clean_max_loss recovery_max_loss loss_settle_seconds recovery_settle_seconds <<< "$RECOVERY_SCENARIO"

    # Phase 1: Clean link without applied netem loss.
    echo "Phase 1: Clean link (0% loss)..."
    local result1
    result1=$(ping_through_tunnel)
    capture_telemetry "recovery-clean"
    local loss1
    loss1=${result1%%:*}
    echo "  Tunnel loss: ${loss1}%"

    # Phase 2: Inject the declared loss.
    echo "Phase 2: Inject ${netem_loss}% loss..."
    apply_qdisc "netem loss ${netem_loss}%"
    sleep "$loss_settle_seconds"
    local result2
    result2=$(ping_through_tunnel)
    capture_telemetry "recovery-lossy"
    local loss2
    loss2=${result2%%:*}
    echo "  Tunnel loss: ${loss2}%"
    remove_qdisc || fatal "could not remove recovery qdisc"

    # Phase 3: Remove loss (clean again)
    echo "Phase 3: Remove loss (clean again)..."
    sleep "$recovery_settle_seconds"
    local result3
    result3=$(ping_through_tunnel)
    capture_telemetry "recovery-recovered"
    local loss3
    loss3=${result3%%:*}
    echo "  Tunnel loss: ${loss3}%"

    if [ "$loss1" -le "$clean_max_loss" ] && [ "$loss3" -le "$recovery_max_loss" ]; then
        echo "PASS: clean=${loss1}%, loss=${loss2}%, recovered=${loss3}%"
        PASS=$((PASS + 1))
    else
        echo "FAIL: clean=${loss1}%, loss=${loss2}%, recovered=${loss3}%"
        FAIL=$((FAIL + 1))
    fi

    if ! check_panics; then
        echo "FAIL: panic detected"
        FAIL=$((FAIL + 1))
    fi
    preserve_failure_if_requested
}

# --- Main ---
echo "=== FEC Network Adversity Test Suite (TODO-425) ==="
echo "Selected suite: ${ADVERSITY_SUITE}"
echo "Ping contract: ${ADVERSITY_PING_COUNT} @ ${ADVERSITY_PING_INTERVAL}s interval"
echo "Loss contract: ${LOSS_SCENARIOS[*]} (netem-loss:max-tunnel-loss)"
echo "Jitter contract: ${JITTER_SCENARIOS[*]} (jitter-ms:base-delay-ms:correlation:max-tunnel-loss)"
echo "Bandwidth contract: ${BANDWIDTH_SCENARIOS[*]} (rate:burst:latency:max-tunnel-loss)"
echo "RTT contract: ${RTT_SCENARIOS[*]} (delay-ms:netem-loss:max-tunnel-loss)"
echo "Combined contract: ${COMBINED_SCENARIO} (delay-ms:jitter-ms:correlation:netem-loss:rate:burst:latency:max-tunnel-loss)"
echo "Recovery contract: ${RECOVERY_SCENARIO} (netem-loss:clean-max-loss:recovery-max-loss:loss-settle-seconds:recovery-settle-seconds)"

case "$ADVERSITY_SUITE" in
    all)
        test_loss_sweep
        test_jitter_sweep
        test_bandwidth
        test_rtt_variation
        test_combined_adversity
        test_adversity_recovery
        ;;
    loss) test_loss_sweep ;;
    jitter) test_jitter_sweep ;;
    bandwidth) test_bandwidth ;;
    rtt) test_rtt_variation ;;
    combined) test_combined_adversity ;;
    recovery) test_adversity_recovery ;;
esac

cleanup_owned_resources || fatal "could not clean final owned resources"
preserve_telemetry_evidence || fatal "could not preserve telemetry evidence"

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
