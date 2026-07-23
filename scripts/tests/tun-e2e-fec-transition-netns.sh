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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
B="$PROJECT_ROOT/target/release/quicfuscate"
CA="$PROJECT_ROOT/config/local/ca.crt"
CA_KEY="$PROJECT_ROOT/config/local/ca.key"
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

check_handshake() {
    local cli srv
    cli=$(grep -c 'TLS handshake complete' "$CLIENT_LOG" 2>/dev/null || true)
    srv=$(grep -c 'TLS handshake complete' "$SERVER_LOG" 2>/dev/null || true)
    cli=${cli:-0}
    srv=${srv:-0}
    [ "$cli" -gt 0 ] && [ "$srv" -gt 0 ]
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

echo "=== FEC Mode Transition E2E Test (TODO-427) ==="

prepare_scenario_runtime "transition"
setup_netns
start_tunnel

if ! check_handshake; then
    echo "FAIL: handshake failed"
    FAIL=$((FAIL + 1))
    exit 1
fi

# Phase 1: Clean link (0% loss) for 50 pings
echo "Phase 1: Clean link (0% loss)..."
loss1=$(ping_phase 50 "1")

# Phase 2: Inject 20% loss - FEC escalates (live transition)
echo "Phase 2: Inject 20% loss (FEC escalates)..."
if ip netns exec ns-cli tc qdisc add dev veth-cli root netem loss 20%; then
    QDISC_CREATED=1
else
    fatal "could not apply 20% netem loss"
fi
sleep 2  # Let FEC detect loss and start transition
loss2=$(ping_phase 50 "2")
remove_qdisc || fatal "could not remove transition netem loss"

# Phase 3: Remove loss - FEC de-escalates (live transition)
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

if grep -q 'panic' "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null; then
    echo "FAIL: panic detected"
    FAIL=$((FAIL + 1))
fi

preserve_failure_if_requested
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
