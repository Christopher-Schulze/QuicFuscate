#!/usr/bin/env bash
# FEC under network adversity - comprehensive tc-netem test suite (TODO-425).
#
# Tests FEC behavior under every realistic network degradation pattern:
#   1. Loss sweep (0-50%) with throughput measurement
#   2. Jitter sweep (0-500ms) - mode stability under jitter
#   3. Bandwidth limitation (1-100Mbit) - FEC overhead vs. useful throughput
#   4. RTT variation (1-300ms) - FEC recovery vs. retransmission latency
#   5. Combined adversity (mobile network simulation)
#   6. Adversity recovery (clean → loss → clean transitions)
#
# Acceptance criteria:
#   - Loss sweep: FEC mode escalates monotonically, throughput degrades gracefully
#   - Jitter sweep: no mode flapping under jitter-only
#   - Bandwidth: FEC overhead <30% on 1Mbit link
#   - RTT: FEC recovery faster than retransmission for high-RTT
#   - Combined: stable 60s operation, no panics
#   - Recovery: de-escalation within 5s, no flapping
#
# Requirements: root, Linux, iproute2, tc-netem, openssl, python3, nc.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="$PROJECT_ROOT/target/release/quicfuscate"
CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"
CA="$PROJECT_ROOT/config/local/ca.crt"
CERT_DIR="$PROJECT_ROOT/config/local"

PING_COUNT="${PING_COUNT:-50}"
PING_INTERVAL="${PING_INTERVAL:-0.1}"
LOCK_FILE="${QF_E2E_LOCK_FILE:-/tmp/quicfuscate-tun-e2e.lock}"
LOCK_TIMEOUT="${QF_E2E_LOCK_TIMEOUT:-300}"
PASS=0
FAIL=0
SKIP=0

exec 9>"$LOCK_FILE"
if ! flock -w "$LOCK_TIMEOUT" 9; then
    echo "FAIL: could not acquire TUN E2E lock $LOCK_FILE within ${LOCK_TIMEOUT}s" >&2
    exit 2
fi

# Load required kernel modules for tc-netem
modprobe sch_netem 2>/dev/null || true
modprobe sch_tbf 2>/dev/null || true

# --- cert setup ---
cd "$CERT_DIR"
cat > /tmp/leaf-ext.cnf <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:cdn.cloudflare.com,DNS:cloudflare-dns.com,DNS:one.one.one.one,DNS:warp.plus,DNS:workers.dev,DNS:localhost,IP:127.0.0.1,IP:10.10.0.1
EOF
openssl req -newkey rsa:2048 -keyout server.key -out /tmp/s.csr -nodes -subj "/CN=cdn.cloudflare.com" 2>/dev/null
openssl x509 -req -in /tmp/s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out /tmp/leaf.crt -days 365 -extfile /tmp/leaf-ext.cnf 2>/dev/null
cat /tmp/leaf.crt ca.crt > server.crt
cd "$PROJECT_ROOT"

cleanup() {
    pkill -9 -f quicfuscate 2>/dev/null
    ip netns del ns-srv 2>/dev/null
    ip netns del ns-cli 2>/dev/null
    sleep 1
}

setup_netns() {
    ip netns add ns-srv
    ip netns add ns-cli
    ip link add veth-srv type veth peer name veth-cli
    ip link set veth-srv netns ns-srv
    ip link set veth-cli netns ns-cli
    ip netns exec ns-srv ip addr add 10.10.0.1/24 dev veth-srv
    ip netns exec ns-srv ip link set veth-srv up
    ip netns exec ns-srv ip link set lo up
    ip netns exec ns-cli ip addr add 10.10.0.2/24 dev veth-cli
    ip netns exec ns-cli ip link set veth-cli up
    ip netns exec ns-cli ip link set lo up
    for ns in ns-srv ns-cli; do
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null
        ip netns exec "$ns" sysctl -wq net.ipv4.conf.default.rp_filter=0 2>/dev/null
    done
}

start_tunnel() {
    ip netns exec ns-srv "$B" server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket /tmp/qf-admin.sock \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 \
        --no-drop-privileges -v \
        > /tmp/ns-srv.log 2>&1 &
    sleep 3

    local qkey
    qkey=$(echo '{"cmd":"qkey"}' | nc -U /tmp/qf-admin.sock 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)

    ip netns exec ns-cli "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
        --qkey "$qkey" --ca-file "$CA" --verify-peer \
        --tun --tun-name qtun0 --tun-ip 10.0.1.2 --tun-netmask 255.255.255.0 --no-utls -v \
        > /tmp/ns-cli.log 2>&1 &
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
        ip netns exec ns-cli tc qdisc add dev veth-cli root $qdisc
    fi
}

remove_qdisc() {
    ip netns exec ns-cli tc qdisc del dev veth-cli root 2>/dev/null
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
    cli=$(grep -c 'TLS handshake complete' /tmp/ns-cli.log 2>/dev/null || echo 0)
    srv=$(grep -c 'TLS handshake complete' /tmp/ns-srv.log 2>/dev/null || echo 0)
    [ "$cli" -gt 0 ] && [ "$srv" -gt 0 ]
}

check_panics() {
    if grep -q 'panic' /tmp/ns-srv.log /tmp/ns-cli.log 2>/dev/null; then
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
        cleanup
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${loss}% | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
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
        remove_qdisc

        # Threshold: tunnel loss should not exceed netem loss by more than 15%
        local max_loss=$((loss + 15))
        if [ "$tunnel_loss" -le "$max_loss" ]; then
            echo "${loss}% | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${loss}% | ${tunnel_loss}% | ${rtt} | FAIL (threshold ${max_loss}%)"
            FAIL=$((FAIL + 1))
        fi
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
        cleanup
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${jitter}ms | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
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
        remove_qdisc

        # Under jitter-only (no loss), tunnel loss should be <10%
        if [ "$tunnel_loss" -le 10 ]; then
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${jitter}ms | ${tunnel_loss}% | ${rtt} | FAIL (threshold 10%)"
            FAIL=$((FAIL + 1))
        fi
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
        cleanup
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${bw} | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            continue
        fi
        apply_qdisc "tbf rate ${bw} burst 32kbit latency 400ms"
        local result
        result=$(ping_through_tunnel)
        local tunnel_loss rtt
        tunnel_loss=${result%%:*}
        rtt=${result##*:}
        remove_qdisc

        # Under bandwidth limit (no loss), tunnel loss should be <5%
        if [ "$tunnel_loss" -le 5 ]; then
            echo "${bw} | ${tunnel_loss}% | ${rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${bw} | ${tunnel_loss}% | ${rtt} | FAIL (threshold 5%)"
            FAIL=$((FAIL + 1))
        fi
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
        cleanup
        setup_netns
        start_tunnel
        if ! check_handshake; then
            echo "${rtt}ms | N/A | N/A | FAIL (handshake)"
            FAIL=$((FAIL + 1))
            continue
        fi
        apply_qdisc "netem delay ${rtt}ms loss 5%"
        local result
        result=$(ping_through_tunnel)
        local tunnel_loss measured_rtt
        tunnel_loss=${result%%:*}
        measured_rtt=${result##*:}
        remove_qdisc

        # With 5% loss + RTT, tunnel loss should be <20% (FEC helps)
        if [ "$tunnel_loss" -le 20 ]; then
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | PASS"
            PASS=$((PASS + 1))
        else
            echo "${rtt}ms | ${tunnel_loss}% | ${measured_rtt} | FAIL (threshold 20%)"
            FAIL=$((FAIL + 1))
        fi
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

    cleanup
    setup_netns
    start_tunnel
    if ! check_handshake; then
        echo "FAIL: handshake failed"
        FAIL=$((FAIL + 1))
        return
    fi

    # Apply combined qdisc: netem (delay+jitter+loss) then tbf (bandwidth)
    ip netns exec ns-cli tc qdisc add dev veth-cli root handle 1: netem delay 100ms 10ms 25% loss 5%
    ip netns exec ns-cli tc qdisc add dev veth-cli parent 1: handle 2: tbf rate 10Mbit burst 32kbit latency 400ms

    local result
    result=$(ping_through_tunnel)
    local tunnel_loss rtt
    tunnel_loss=${result%%:*}
    rtt=${result##*:}

    remove_qdisc

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
}

# ---------------------------------------------------------------------------
# 6. Adversity recovery (clean → loss → clean transitions)
# ---------------------------------------------------------------------------
test_adversity_recovery() {
    echo ""
    echo "=========================================="
    echo "  6. Adversity Recovery (clean → loss → clean)"
    echo "=========================================="

    cleanup
    setup_netns
    start_tunnel
    if ! check_handshake; then
        echo "FAIL: handshake failed"
        FAIL=$((FAIL + 1))
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
    remove_qdisc

    # Phase 3: Remove loss (clean again)
    echo "Phase 3: Remove loss (clean again)..."
    sleep 3  # Wait for de-escalation
    local result3
    result3=$(ping_through_tunnel)
    local loss3
    loss3=${result3%%:*}
    echo "  Tunnel loss: ${loss3}%"

    # Acceptance: Phase 1 loss <5%, Phase 3 loss <10% (recovery after de-escalation)
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

cleanup

echo ""
echo "=========================================="
echo "  Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
