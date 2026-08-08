#!/usr/bin/env bash
# Description: Contract check for the netfilter fast-path helper.
#
# This helper inserts an unconditional top-of-chain ACCEPT, so two properties are
# safety-critical: it must only ever delete rules it created, and it must refuse a
# port outside the supported service policy. Both are checked here without touching a
# real firewall, using the helper's own dry-run command output as the evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${PROJECT_ROOT}"
HELPER="${PROJECT_ROOT}/scripts/install/setup-netfilter-fastpath.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR]"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/smoke/$(basename "$0" .sh)-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

FAILURES=0
fail() { echo "[FAIL] $1" >&2; FAILURES=$((FAILURES + 1)); }

echo "> rejects ports outside the supported service policy"
for bad in 0 22 53 1023 65536 99999 notaport -- ""; do
  if bash "$HELPER" --dry-run "$bad" >"$OUTPUT_DIR/bad.log" 2>&1; then
    # An empty argument is indistinguishable from no argument, so it legitimately
    # falls back to the default port; every other value must be refused.
    [[ -z "$bad" ]] || fail "port ${bad:-<empty>} was accepted"
  else
    [[ -z "$bad" ]] && fail "an empty argument must fall back to the default port"
  fi
done

echo "> rejects unknown options instead of treating them as a port"
if bash "$HELPER" --dry-run --definitely-not-an-option >/dev/null 2>&1; then
  fail "an unknown option was accepted"
fi

echo "> every emitted rule carries the ownership comment"
INSERT_LOG="$OUTPUT_DIR/insert.log"
bash "$HELPER" --dry-run 4433 > "$INSERT_LOG" 2>&1
while IFS= read -r line; do
  case "$line" in
    dry-run:*iptables*)
      grep -q -- "--comment quicfuscate-fastpath" <<<"$line" \
        || fail "an iptables command without the owner comment: $line"
      ;;
  esac
done < "$INSERT_LOG"
grep -q -- "-I INPUT 1 -p udp --dport 4433 -m comment --comment quicfuscate-fastpath -j ACCEPT" \
  "$INSERT_LOG" || fail "the insert command does not match the owned rule spec"

echo "> removal only ever targets the owned rule"
REMOVE_LOG="$OUTPUT_DIR/remove.log"
bash "$HELPER" --dry-run --remove 4433 > "$REMOVE_LOG" 2>&1
if grep -E "^dry-run: iptables -D" "$REMOVE_LOG" | grep -qv -- "--comment quicfuscate-fastpath"; then
  fail "a delete command would match rules this script did not create"
fi
grep -qE "^dry-run: iptables -D INPUT -p udp --dport 4433 -m comment" "$REMOVE_LOG" \
  || fail "removal did not emit an owned delete"

echo "> a custom in-policy port is accepted and stays owned"
CUSTOM_LOG="$OUTPUT_DIR/custom.log"
bash "$HELPER" --dry-run 8443 > "$CUSTOM_LOG" 2>&1
grep -q -- "--dport 8443 -m comment --comment quicfuscate-fastpath" "$CUSTOM_LOG" \
  || fail "a supported custom port did not produce an owned rule"

if ((FAILURES)); then
  echo "[FAIL] ${FAILURES} netfilter fast-path contract case(s) failed" >&2
  exit 1
fi
echo "[OK] netfilter fast-path ownership and port policy hold"
