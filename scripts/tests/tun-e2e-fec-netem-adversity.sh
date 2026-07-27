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

PING_COUNT="${PING_COUNT:-50}"
PING_INTERVAL="${PING_INTERVAL:-0.1}"
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
        fatal "could not get qkey from server"
    fi

    ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
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
    ping_output=$(ip netns exec ns-cli ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 5 -I qtun0 10.0.1.1 2>&1)
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

# ---------------------------------------------------------------------------
# 1. Loss sweep (0-50%)
# ---------------------------------------------------------------------------
test_loss_sweep() {
    echo ""
    echo "=========================================="
    echo "  1. Loss Sweep (0-50%)"
    echo "=========================================="
    echo "loss% | tunnel_loss% | rtt_ms | status"

    for loss in 0 1 5 10 25 50; do
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
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        # Threshold: tunnel loss should not exceed netem loss by more than 15%
        local max_loss=$((loss + 15))
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
# 2. Jitter sweep (0-500ms)
# ---------------------------------------------------------------------------
test_jitter_sweep() {
    echo ""
    echo "=========================================="
    echo "  2. Jitter Sweep (0-500ms, no loss)"
    echo "=========================================="
    echo "jitter_ms | tunnel_loss% | rtt_ms | status"

    for jitter in 0 10 50 100 200 500; do
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
            apply_qdisc "netem delay 50ms ${jitter}ms 25%"
        fi
        local result
        result=$(ping_through_tunnel)
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        # Under jitter-only (no loss), tunnel loss should be <10%
        if [ "$tunnel_loss" -le 10 ]; then
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | FAIL (threshold 10%)"
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
# 3. Bandwidth limitation (1-100Mbit)
# ---------------------------------------------------------------------------
test_bandwidth() {
    echo ""
    echo "=========================================="
    echo "  3. Bandwidth Limitation (1-100Mbit)"
    echo "=========================================="
    echo "bandwidth | tunnel_loss% | rtt_ms | status"

    for bw in 100Mbit 50Mbit 10Mbit 5Mbit 1Mbit; do
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
        apply_qdisc "tbf rate ${bw} burst 32kbit latency 400ms"
        local result
        result=$(ping_through_tunnel)
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}

        # Under bandwidth limit (no loss), tunnel loss should be <5%
        if [ "$tunnel_loss" -le 5 ]; then
            echo "${bw} | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${bw} | ${tunnel_loss}% | ${rtt} | FAIL (threshold 5%)"
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
# 4. RTT variation (1-300ms with 5% loss)
# ---------------------------------------------------------------------------
test_rtt_variation() {
    echo ""
    echo "=========================================="
    echo "  4. RTT Variation (1-300ms + 5% loss)"
    echo "=========================================="
    echo "rtt_ms | tunnel_loss% | measured_rtt_ms | status"

    for rtt in 1 10 50 100 200 300; do
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
        apply_qdisc "netem delay ${rtt}ms loss 5%"
        local result
        result=$(ping_through_tunnel)
        local tunnel_loss measured_rtt
        tunnel_loss=${result%%:*}
        measured_rtt=${result##*:}

        # With 5% loss plus RTT, this liveness scenario requires tunnel loss <=20%.
        if [ "$tunnel_loss" -le 20 ]; then
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | FAIL (threshold 20%)"
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
# 5. Combined adversity (mobile network simulation)
# ---------------------------------------------------------------------------
test_combined_adversity() {
    echo ""
    echo "=========================================="
    echo "  5. Combined Adversity (Mobile Network)"
    echo "=========================================="
    echo "  100ms RTT + 10ms jitter + 5% loss + 10Mbit"

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
    if ip netns exec ns-cli tc qdisc add dev veth-cli root handle 1: netem delay 100ms 10ms 25% loss 5%; then
        QDISC_CREATED=1
    else
        fatal "could not apply combined root netem qdisc"
    fi
    ip netns exec ns-cli tc qdisc add dev veth-cli parent 1: handle 2: tbf rate 10Mbit burst 32kbit latency 400ms \
        || fatal "could not apply combined child tbf qdisc"

    local result
    result=$(ping_through_tunnel)
    local tunnel_loss rtt
    tunnel_loss=${result%%:*}
    rtt=${result##*:}

    # Under combined adversity, tunnel loss should be <25%
    if [ "$tunnel_loss" -le 25 ]; then
        echo "PASS: ${tunnel_loss}% tunnel loss, ${rtt} rtt"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${tunnel_loss}% tunnel loss (threshold 25%)"
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
# 6. Adversity recovery (clean → loss → clean transitions)
# ---------------------------------------------------------------------------
test_adversity_recovery() {
    echo ""
    echo "=========================================="
    echo "  6. Adversity Recovery (clean → loss → clean)"
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

    # Phase 1: Clean link (0% loss)
    echo "Phase 1: Clean link (0% loss)..."
    local result1
    result1=$(ping_through_tunnel)
    local loss1
    loss1=${result1%%:*}
    echo "  Tunnel loss: ${loss1}%"

    # Phase 2: Inject 20% loss
    echo "Phase 2: Inject 20% loss..."
    apply_qdisc "netem loss 20%"
    sleep 2
    local result2
    result2=$(ping_through_tunnel)
    local loss2
    loss2=${result2%%:*}
    echo "  Tunnel loss: ${loss2}%"
    remove_qdisc || fatal "could not remove recovery qdisc"

    # Phase 3: Remove loss (clean again)
    echo "Phase 3: Remove loss (clean again)..."
    sleep 3  # Allow the clean-link recovery observation to begin.
    local result3
    result3=$(ping_through_tunnel)
    local loss3
    loss3=${result3%%:*}
    echo "  Tunnel loss: ${loss3}%"

    # Acceptance: Phase 1 loss <5%, Phase 3 loss <10% for clean-link recovery liveness.
    if [ "$loss1" -le 5 ] && [ "$loss3" -le 10 ]; then
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
echo "Ping count: ${PING_COUNT} @ ${PING_INTERVAL}s interval"

test_loss_sweep
test_jitter_sweep
test_bandwidth
test_rtt_variation
test_combined_adversity
test_adversity_recovery

cleanup_owned_resources || fatal "could not clean final owned resources"

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
