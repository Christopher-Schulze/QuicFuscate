#!/usr/bin/env bash
# Regression proof for exact lifecycle ownership in specialized TUN/FEC E2E harnesses.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESSES=(
  "$SCRIPT_DIR/tun-e2e-fec-netns.sh"
  "$SCRIPT_DIR/tun-e2e-fec-burst-netns.sh"
  "$SCRIPT_DIR/tun-e2e-fec-transition-netns.sh"
  "$SCRIPT_DIR/tun-e2e-fec-netem-adversity.sh"
)
RUNTIME_DIR=""
SENTINEL_PID=""
SENTINEL_NAMESPACE_CREATED=0
SENTINEL_LINK_CREATED=0

stop_exact_pid() {
  local pid="$1"
  if [ -z "$pid" ]; then
    return
  fi
  kill -9 "$pid" 2>/dev/null || true
}

cleanup() {
  stop_exact_pid "$SENTINEL_PID"
  if [ "$SENTINEL_NAMESPACE_CREATED" = "1" ]; then
    ip netns del ns-srv 2>/dev/null || true
  fi
  if [ "$SENTINEL_LINK_CREATED" = "1" ]; then
    ip link del veth-srv 2>/dev/null || true
  fi
  if [ -n "$RUNTIME_DIR" ]; then
    case "$RUNTIME_DIR" in
      /tmp/quicfuscate-e2e-ownership.*) rm -rf -- "$RUNTIME_DIR" ;;
      *) echo "FAIL: refusing to remove unexpected test runtime: $RUNTIME_DIR" >&2 ;;
    esac
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP: specialized TUN E2E ownership regression requires Linux"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: specialized TUN E2E ownership regression requires root"
  exit 0
fi

RUNTIME_DIR="$(mktemp -d /tmp/quicfuscate-e2e-ownership.XXXXXX)" \
  || fail "could not create regression runtime"

bash -c 'exec -a quicfuscate-sentinel sleep 300' &
SENTINEL_PID=$!
sleep 0.1
kill -0 "$SENTINEL_PID" 2>/dev/null || fail "unrelated process sentinel did not start"
ps -p "$SENTINEL_PID" -o command= | grep -q 'quicfuscate-sentinel' \
  || fail "unrelated process sentinel lacks the product-name marker"

cleanup_recorded_pids() {
  local pid_file="$1"
  local pid
  while IFS= read -r pid; do
    stop_exact_pid "$pid"
  done < "$pid_file"
}

run_lifecycle_mode() {
  local harness="$1"
  local mode="$2"
  local expected_status="$3"
  local expect_alive="$4"
  local name
  local pid_file
  local status
  local pid
  local lifecycle_error=""
  name="$(basename "$harness" .sh)"
  pid_file="$RUNTIME_DIR/${name}-${mode}.pids"

  QF_E2E_LOCK_FILE="$RUNTIME_DIR/lock" \
  QF_E2E_OWNERSHIP_SELF_TEST=1 \
  QF_E2E_OWNERSHIP_SELF_TEST_MODE="$mode" \
  QF_E2E_OWNERSHIP_PID_FILE="$pid_file" \
    bash "$harness" >/dev/null 2>&1
  status=$?

  if [ "$status" -ne "$expected_status" ]; then
    [ -f "$pid_file" ] && cleanup_recorded_pids "$pid_file"
    fail "$name $mode returned $status, expected $expected_status"
  fi
  [ -s "$pid_file" ] || fail "$name $mode did not record owned child PIDs"

  while IFS= read -r pid; do
    if [ "$expect_alive" = "1" ]; then
      if ! kill -0 "$pid" 2>/dev/null; then
        lifecycle_error="$name $mode did not preserve owned child $pid"
      fi
    elif kill -0 "$pid" 2>/dev/null; then
      lifecycle_error="$name $mode leaked owned child $pid"
    fi
  done < "$pid_file"

  if [ "$expect_alive" = "1" ] || [ -n "$lifecycle_error" ]; then
    cleanup_recorded_pids "$pid_file"
  fi
  [ -z "$lifecycle_error" ] || fail "$lifecycle_error"
  kill -0 "$SENTINEL_PID" 2>/dev/null \
    || fail "$name $mode terminated the unrelated process sentinel"
}

for harness in "${HARNESSES[@]}"; do
  run_lifecycle_mode "$harness" exit 23 0
  run_lifecycle_mode "$harness" signal 143 0
  run_lifecycle_mode "$harness" keep 24 1
done

ip netns add ns-srv || fail "could not create unowned namespace sentinel"
SENTINEL_NAMESPACE_CREATED=1
for harness in "${HARNESSES[@]}"; do
  QF_E2E_LOCK_FILE="$RUNTIME_DIR/lock" \
  QF_E2E_OWNERSHIP_SELF_TEST=1 \
    bash "$harness" >/dev/null 2>&1
  status=$?
  [ "$status" -eq 2 ] || fail "$(basename "$harness") did not refuse the unowned namespace"
  ip netns list | grep -Eq '^ns-srv([[:space:]]|$)' \
    || fail "$(basename "$harness") deleted the unowned namespace"
done
ip netns del ns-srv || fail "could not remove namespace sentinel"
SENTINEL_NAMESPACE_CREATED=0

ip link add veth-srv type veth peer name veth-cli \
  || fail "could not create unowned link sentinel"
SENTINEL_LINK_CREATED=1
for harness in "${HARNESSES[@]}"; do
  QF_E2E_LOCK_FILE="$RUNTIME_DIR/lock" \
  QF_E2E_OWNERSHIP_SELF_TEST=1 \
    bash "$harness" >/dev/null 2>&1
  status=$?
  [ "$status" -eq 2 ] || fail "$(basename "$harness") did not refuse the unowned links"
  ip link show dev veth-srv >/dev/null 2>&1 \
    || fail "$(basename "$harness") deleted the unowned link"
done
ip link del veth-srv || fail "could not remove link sentinel"
SENTINEL_LINK_CREATED=0

kill -0 "$SENTINEL_PID" 2>/dev/null \
  || fail "unrelated process sentinel did not survive the full regression"

echo "PASS: specialized TUN/FEC harnesses clean only owned children and preserve unowned resources"
