#!/usr/bin/env bash
# Process-real negative and rollback proof for Linux TUN provisioning.
#
# The harness runs the real server binary inside one isolated network namespace
# and a private mount namespace with an isolated /run. Failed creation must not
# leave an owned TUN interface behind, while pre-existing resources stay intact.
# The private runtime also prevents a failed proof from contaminating later jobs.
#
# Covered cases:
#   - overlong requested interface name
#   - pre-existing duplicate interface name
#   - permission denial without CAP_NET_ADMIN
#   - conflicting address after TUNSETIFF
#   - missing interface race during routing setup
#   - routing setup failure, retry, and zero owned residue
#
# Requirements: Linux, root, iproute2, mount, openssl, runuser, unshare, and a built binary.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
BINARY="${QF_E2E_BINARY:-$PROJECT_ROOT/target/release/quicfuscate}"
RUNTIME_DIR=""
ISOLATED_RUN_DIR=""
CERT=""
KEY=""
NOBODY_RUNTIME_DIR=""
NOBODY_BINARY=""
NAMESPACE="qf-tun-provision-$$"
SERVER_PID=""
PORT=$((43000 + ($$ % 1000)))
NAMESPACE_CREATED=0
KEEP_RUNTIME="${QF_TUN_PROVISIONING_KEEP:-0}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

is_live_pid() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || return 1
  local state
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$state" ] && [ "${state#Z}" = "$state" ]
}

stop_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  if is_live_pid "$pid"; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      is_live_pid "$pid" || break
      sleep 0.1
    done
    if is_live_pid "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  stop_pid "$SERVER_PID"
  SERVER_PID=""
  if [ "$NAMESPACE_CREATED" = "1" ]; then
    ip netns del "$NAMESPACE" 2>/dev/null || true
    NAMESPACE_CREATED=0
  fi
  if [ -n "$RUNTIME_DIR" ]; then
    case "$RUNTIME_DIR" in
      /tmp/quicfuscate-tun-provisioning.*)
        if [ "$KEEP_RUNTIME" = "1" ]; then
          echo "Evidence retained at $RUNTIME_DIR"
        else
          rm -rf -- "$RUNTIME_DIR"
        fi
        ;;
      *) echo "FAIL: refusing to remove unexpected runtime directory $RUNTIME_DIR" >&2 ;;
    esac
  fi
}
trap cleanup EXIT

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: Linux TUN provisioning proof requires Linux"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: Linux TUN provisioning proof requires root"
  exit 0
fi
for command_name in ip mount openssl ps runuser unshare; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: $command_name"
done
if [ ! -x "$BINARY" ]; then
  fail "built QuicFuscate binary is missing or not executable: $BINARY"
fi
if ip netns list | grep -Eq "^$NAMESPACE([[:space:]]|$)"; then
  fail "test namespace already exists; refusing to delete unowned namespace $NAMESPACE"
fi

RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-tun-provisioning.XXXXXX)" ||
  fail "could not create isolated runtime directory"
chmod 755 "$RUNTIME_DIR" || fail "could not make test certificates readable"
ISOLATED_RUN_DIR="$RUNTIME_DIR/run"
mkdir "$ISOLATED_RUN_DIR" || fail "could not create isolated /run backing directory"
chmod 755 "$ISOLATED_RUN_DIR" || fail "could not make isolated /run backing directory accessible"
CERT="$RUNTIME_DIR/server.crt"
KEY="$RUNTIME_DIR/server.key"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=QuicFuscate TUN provisioning proof" \
  -keyout "$KEY" -out "$CERT" >/dev/null 2>&1 ||
  fail "could not create isolated test certificate"
chmod 644 "$CERT" "$KEY" || fail "could not make test certificate readable"

NOBODY_RUNTIME_DIR="$RUNTIME_DIR/nobody"
mkdir "$NOBODY_RUNTIME_DIR" || fail "could not create permission-test runtime directory"
chmod 777 "$NOBODY_RUNTIME_DIR" || fail "could not make permission-test runtime directory writable"
NOBODY_BINARY="$RUNTIME_DIR/quicfuscate"
cp -- "$BINARY" "$NOBODY_BINARY" || fail "could not stage permission-test binary"
chmod 755 "$NOBODY_BINARY" || fail "could not make permission-test binary executable"

ip netns add "$NAMESPACE" || fail "could not create isolated network namespace"
NAMESPACE_CREATED=1
ip netns exec "$NAMESPACE" ip link set lo up ||
  fail "could not activate isolated loopback"

server_command() {
  local run_as="$1"
  local label="$2"
  local tun_name="$3"
  local tun_ip="$4"
  local tun_netmask="$5"
  local log="$RUNTIME_DIR/${label}.log"
  local binary="$BINARY"
  local qkey_store="$RUNTIME_DIR/${label}-qkeys.json"
  local -a payload
  if [ "$run_as" = "nobody" ]; then
    binary="$NOBODY_BINARY"
    qkey_store="$NOBODY_RUNTIME_DIR/${label}-qkeys.json"
  fi
  payload=(
    "$binary" server
    --cert "$CERT"
    --key "$KEY"
    --listen "127.0.0.1:$PORT"
    --qkey-store "$qkey_store"
    --no-drop-privileges
    --tun
    --tun-name "$tun_name"
    --tun-ip "$tun_ip"
    --tun-netmask "$tun_netmask"
  )
  if [ "$run_as" = "nobody" ]; then
    payload=(runuser -u nobody -- "${payload[@]}")
  fi
  local -a command=(
    ip netns exec "$NAMESPACE"
    unshare --mount --propagation private --
    /bin/bash -c '
      set -eu
      isolated_run=$1
      shift
      mount --bind "$isolated_run" /run
      exec "$@"
    ' qf-tun-provisioning-mount "$ISOLATED_RUN_DIR"
    "${payload[@]}"
  )
  "${command[@]}" >"$log" 2>&1 &
  SERVER_PID=$!
}

expect_failure() {
  local label="$1"
  local run_as="$2"
  local tun_name="$3"
  local tun_ip="$4"
  local tun_netmask="$5"
  server_command "$run_as" "$label" "$tun_name" "$tun_ip" "$tun_netmask"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    is_live_pid "$SERVER_PID" || break
    sleep 0.1
  done
  if is_live_pid "$SERVER_PID"; then
    stop_pid "$SERVER_PID"
    SERVER_PID=""
    fail "$label unexpectedly stayed alive; see $RUNTIME_DIR/$label.log"
  fi
  wait "$SERVER_PID"
  local status=$?
  SERVER_PID=""
  [ "$status" -ne 0 ] || fail "$label unexpectedly succeeded"
}

assert_interface_absent() {
  local name="$1"
  if ip netns exec "$NAMESPACE" ip link show dev "$name" >/dev/null 2>&1; then
    fail "owned interface $name remains after failed provisioning"
  fi
}

assert_interface_present() {
  local name="$1"
  ip netns exec "$NAMESPACE" ip link show dev "$name" >/dev/null 2>&1 ||
    fail "sentinel interface $name disappeared"
}

LONG_NAME="qf-name-0123456789"
expect_failure "overlong-name" root "$LONG_NAME" 10.20.0.1 255.255.255.0
assert_interface_absent "$LONG_NAME"

DUPLICATE_NAME="qf-duplicate"
ip netns exec "$NAMESPACE" ip tuntap add dev "$DUPLICATE_NAME" mode tun ||
  fail "could not create duplicate-interface sentinel"
expect_failure "duplicate-name" root "$DUPLICATE_NAME" 10.20.1.1 255.255.255.0
assert_interface_present "$DUPLICATE_NAME"
ip netns exec "$NAMESPACE" ip tuntap del dev "$DUPLICATE_NAME" mode tun ||
  fail "could not remove duplicate-interface sentinel"
assert_interface_absent "$DUPLICATE_NAME"

PERMISSION_NAME="qf-permission"
expect_failure "permission-denied" nobody "$PERMISSION_NAME" 10.20.2.1 255.255.255.0
assert_interface_absent "$PERMISSION_NAME"

CONFLICT_NAME="qf-conflict"
CONFLICT_IP="10.20.5.1"
ip netns exec "$NAMESPACE" ip link add eth0 type dummy ||
  fail "could not create the configured-WAN sentinel"
ip netns exec "$NAMESPACE" ip link set eth0 up ||
  fail "could not activate the configured-WAN sentinel"
ip netns exec "$NAMESPACE" ip tuntap add dev "$CONFLICT_NAME" mode tun ||
  fail "could not create conflicting-address sentinel"
ip netns exec "$NAMESPACE" ip addr add "$CONFLICT_IP/24" dev "$CONFLICT_NAME" ||
  fail "could not assign conflicting-address sentinel"
expect_failure "conflicting-address" root "$CONFLICT_NAME-new" "$CONFLICT_IP" 255.255.255.0
grep -Eiq "file exists|already exists|cannot assign requested address|address.*exist" \
  "$RUNTIME_DIR/conflicting-address.log" ||
  fail "conflicting-address did not produce an address-conflict diagnostic"
assert_interface_absent "$CONFLICT_NAME-new"
assert_interface_present "$CONFLICT_NAME"
ip netns exec "$NAMESPACE" ip tuntap del dev "$CONFLICT_NAME" mode tun ||
  fail "could not remove conflicting-address sentinel"
ip netns exec "$NAMESPACE" ip link delete dev eth0 ||
  fail "could not remove the configured-WAN sentinel"

PARTIAL_NAME="qf-partial"
expect_failure "routing-failure" root "$PARTIAL_NAME" 10.20.3.1 255.255.255.0
assert_interface_absent "$PARTIAL_NAME"
expect_failure "routing-retry" root "$PARTIAL_NAME" 10.20.3.1 255.255.255.0
assert_interface_absent "$PARTIAL_NAME"
[ ! -e "$ISOLATED_RUN_DIR/quicfuscate/routing/firewall-owner.json" ] ||
  fail "ordinary routing rollback left isolated durable firewall ownership residue"

MISSING_NAME="qf-missing"
ip netns exec "$NAMESPACE" ip link add eth0 type dummy ||
  fail "could not create the missing-interface WAN sentinel"
ip netns exec "$NAMESPACE" ip link set eth0 up ||
  fail "could not activate the missing-interface WAN sentinel"
server_command root "missing-interface" "$MISSING_NAME" 10.20.4.1 255.255.255.0
deleted=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if ip netns exec "$NAMESPACE" ip link show dev "$MISSING_NAME" >/dev/null 2>&1; then
    ip netns exec "$NAMESPACE" ip link delete dev "$MISSING_NAME" ||
      fail "could not delete the owned interface for the missing-interface race"
    deleted=1
    break
  fi
  is_live_pid "$SERVER_PID" || break
  sleep 0.1
done
[ "$deleted" = "1" ] || fail "missing-interface race did not observe the created TUN"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  is_live_pid "$SERVER_PID" || break
  sleep 0.1
done
if is_live_pid "$SERVER_PID"; then
  stop_pid "$SERVER_PID"
  SERVER_PID=""
  fail "missing-interface case stayed alive; see $RUNTIME_DIR/missing-interface.log"
fi
wait "$SERVER_PID"
missing_status=$?
SERVER_PID=""
[ "$missing_status" -ne 0 ] || fail "missing-interface case unexpectedly succeeded"
assert_interface_absent "$MISSING_NAME"
[ ! -e "$ISOLATED_RUN_DIR/quicfuscate/routing/firewall-owner.json" ] ||
  fail "missing-interface rollback left isolated durable firewall ownership residue"
ip netns exec "$NAMESPACE" ip link delete dev eth0 ||
  fail "could not remove the missing-interface WAN sentinel"

echo "PASS: Linux TUN provisioning rejects invalid/conflicting activation and leaves zero owned residue"
