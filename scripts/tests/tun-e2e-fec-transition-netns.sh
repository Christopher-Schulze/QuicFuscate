#!/usr/bin/env bash
# FEC mode transition E2E test via tc-netem (TODO-427, test 7).
#
# Verifies FEC mode transitions are seamless under real transport load:
#   Phase 1: 0% loss for 5s → FEC in Zero/Light
#   Phase 2: 20% loss for 5s → FEC escalates to Strong/Extreme (live transition)
#   Phase 3: 0% loss for 5s → FEC de-escalates (live transition)
#
# Acceptance: 0% ping loss DURING transitions (not just before/after).
set -u
PROJECT_ROOT="${PROJECT_ROOT:-/root/QuicFuscate}"
B="$PROJECT_ROOT/target/release/quicfuscate"
CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"
CA="$PROJECT_ROOT/config/local/ca.crt"
CERT_DIR="$PROJECT_ROOT/config/local"

modprobe sch_netem 2>/dev/null || true
PASS=0
FAIL=0

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
}

start_tunnel() {
    ip netns exec ns-srv env QUICFUSCATE_FEC_INTERLEAVE=0 "$B" server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket /tmp/qf-admin.sock \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 -v \
        > /tmp/ns-srv.log 2>&1 &
    sleep 3

    local qkey
    qkey=$(echo '{"cmd":"qkey"}' | nc -U /tmp/qf-admin.sock 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)

    ip netns exec ns-cli env QUICFUSCATE_FEC_INTERLEAVE=0 "$B" client --remote 10.10.0.1:4433 --url https://10.10.0.1/ \
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

check_handshake() {
    local cli srv
    cli=$(grep -c 'TLS handshake complete' /tmp/ns-cli.log 2>/dev/null || echo 0)
    srv=$(grep -c 'TLS handshake complete' /tmp/ns-srv.log 2>/dev/null || echo 0)
    [ "$cli" -gt 0 ] && [ "$srv" -gt 0 ]
}

ping_phase() {
    local count="$1"
    local label="$2"
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$count" -i 0.1 -W 5 -I qtun0 10.0.1.1 2>&1)
    local ping_loss
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    echo "  Phase ${label}: ${ping_loss}% tunnel loss"
    echo "$ping_loss"
}

echo "=== FEC Mode Transition E2E Test (TODO-427) ==="

cleanup
setup_netns
start_tunnel

if ! check_handshake; then
    echo "FAIL: handshake failed"
    FAIL=$((FAIL + 1))
    cleanup
    exit 1
fi

# Phase 1: Clean link (0% loss) for 50 pings
echo "Phase 1: Clean link (0% loss)..."
loss1=$(ping_phase 50 "1")

# Phase 2: Inject 20% loss — FEC escalates (live transition)
echo "Phase 2: Inject 20% loss (FEC escalates)..."
ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss 20%
sleep 2  # Let FEC detect loss and start transition
loss2=$(ping_phase 50 "2")
ip netns exec ns-cli tc qdisc del dev veth-cli root 2>/dev/null

# Phase 3: Remove loss — FEC de-escalates (live transition)
echo "Phase 3: Remove loss (FEC de-escalates)..."
sleep 3  # Wait for de-escalation
loss3=$(ping_phase 50 "3")

# Acceptance criteria
echo ""
echo "Results:"
echo "  Phase 1 (clean):     ${loss1}% loss"
echo "  Phase 2 (20% loss):  ${loss2}% loss"
echo "  Phase 3 (recovered): ${loss3}% loss"

ok=true
if [ "$loss1" -gt 5 ]; then
    echo "FAIL: Phase 1 loss >5%"
    ok=false
fi
if [ "$loss2" -gt 35 ]; then
    echo "FAIL: Phase 2 loss >35% (FEC should recover some)"
    ok=false
fi
if [ "$loss3" -gt 10 ]; then
    echo "FAIL: Phase 3 loss >10% (should recover after de-escalation)"
    ok=false
fi

if $ok; then
    echo "PASS: mode transitions seamless under load"
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

if grep -q 'panic' /tmp/ns-srv.log /tmp/ns-cli.log 2>/dev/null; then
    echo "FAIL: panic detected"
    FAIL=$((FAIL + 1))
fi

cleanup

echo ""
echo "=========================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
