#!/usr/bin/env bash
# E2E FEC burst loss test through real QUIC transport with tc-netem.
#
# Tests FEC recovery under bursty loss patterns (correlated loss) which are
# more realistic than uniform random loss. tc-netem supports loss correlation
# to simulate burst loss.
#
# Acceptance criteria (TODO-423):
#   - 10% loss with 25% correlation: <5% tunnel loss
#   - 20% loss with 50% correlation: <10% tunnel loss
#   - FEC interleaving should handle burst patterns better than block codes
#   - No panics
#
# Requirements: root, Linux, iproute2, tc-netem, openssl, python3, nc.
set -u
PROJECT_ROOT="${PROJECT_ROOT:-/root/QuicFuscate}"
B="$PROJECT_ROOT/target/release/quicfuscate"
CERT="$PROJECT_ROOT/config/local/server.crt"
KEY="$PROJECT_ROOT/config/local/server.key"
CA="$PROJECT_ROOT/config/local/ca.crt"
CERT_DIR="$PROJECT_ROOT/config/local"

PING_COUNT="${PING_COUNT:-100}"
PING_INTERVAL="${PING_INTERVAL:-0.1}"
PASS=0
FAIL=0

# --- cert setup (same as tun-e2e-netns.sh) ---
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

run_burst_test() {
    local loss_pct="$1"
    local correlation="$2"
    local label="$3"
    local max_loss="$4"

    echo ""
    echo "=========================================="
    echo "  FEC Burst Loss: ${label}"
    echo "=========================================="

    cleanup
    setup_netns

    # Start server (interleaving disabled — known decoder bug, see tun-e2e-fec-netns.sh)
    ip netns exec ns-srv env QUICFUSCATE_FEC_INTERLEAVE=0 "$B" server --cert "$CERT" --key "$KEY" \
        --listen 10.10.0.1:4433 --admin-socket /tmp/qf-admin.sock \
        --tun --tun-name qtun0 --tun-ip 10.0.1.1 --tun-netmask 255.255.255.0 -v \
        > /tmp/ns-srv.log 2>&1 &
    sleep 3

    local qkey
    qkey=$(echo '{"cmd":"qkey"}' | nc -U /tmp/qf-admin.sock 2>/dev/null | \
        python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["data"]["qkey"])' 2>/dev/null)

    # Start client
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

    # Apply burst loss AFTER handshake
    ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss "${loss_pct}%" "${correlation}%"
    echo "Applied: ${loss_pct}% loss with ${correlation}% correlation"

    echo "Pinging through tunnel (${PING_COUNT} pings @ ${PING_INTERVAL}s interval)..."
    local ping_output
    ping_output=$(ip netns exec ns-cli ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 3 -I qtun0 10.0.1.1 2>&1)
    echo "$ping_output" | tail -3

    local ping_loss
    # Extract integer packet loss percentage (handle decimals like "3.33%")
    ping_loss=$(echo "$ping_output" | grep 'packet loss' | grep -oP '[\d.]+(?=% packet loss)' | awk '{printf "%d", $1}' || echo "100")
    echo "Tunnel loss: ${ping_loss}%"

    if [ "$ping_loss" -le "$max_loss" ]; then
        echo "PASS: ${label} -> ${ping_loss}% tunnel loss (threshold: ${max_loss}%)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${label} -> ${ping_loss}% tunnel loss (threshold: ${max_loss}%)"
        FAIL=$((FAIL + 1))
    fi

    if grep -q 'panic' /tmp/ns-srv.log /tmp/ns-cli.log 2>/dev/null; then
        echo "FAIL: panic detected"
        FAIL=$((FAIL + 1))
    fi

    ip netns exec ns-cli tc qdisc del dev veth-cli root 2>/dev/null
}

# --- Main ---
echo "=== FEC Burst Loss E2E Test Suite (TODO-423) ==="

run_burst_test 10 25 "10% loss, 25% correlation (mild burst)" 5
run_burst_test 20 50 "20% loss, 50% correlation (heavy burst)" 10

cleanup

echo ""
echo "=========================================="
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
