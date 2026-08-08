#!/usr/bin/env bash
# Netfilter fast-path rule for QuicFuscate UDP traffic.
#
# The profiling baseline (docs/profiling/baseline-2026-07.md) shows 15% CPU
# overhead from nft_do_chain evaluating iptables rules for every UDP packet.
# This script inserts a fast-path ACCEPT rule at the top of INPUT for the
# QuicFuscate UDP port, bypassing the full iptables rule chain.
#
# Rule ownership: every rule this script creates carries the comment
# "quicfuscate-fastpath", and removal only ever deletes rules carrying it. The
# previous version matched on protocol, port, and target alone, so a rule an
# operator or a distribution had created with the same match was indistinguishable
# from ours and was deleted by a cleanup run.
#
# Usage:
#   sudo ./setup-netfilter-fastpath.sh [PORT]
#   sudo ./setup-netfilter-fastpath.sh --remove [PORT]
#   ./setup-netfilter-fastpath.sh --dry-run [PORT]
#
# PORT defaults to 4433 (from config/server-linux.default.toml).

set -euo pipefail

readonly RULE_COMMENT="quicfuscate-fastpath"
readonly DEFAULT_PORT=4433
# Inserting an unconditional top-of-chain ACCEPT is a firewall-precedence change, so
# the port it applies to is not accepted blindly. System ports are refused because a
# QuicFuscate listener does not belong there and a typo that opens 22 or 53 ahead of
# every other rule is exactly the damage this bound exists to prevent.
readonly MIN_PORT=1024
readonly MAX_PORT=65535

MODE="insert"
DRY_RUN=0
PORT=""

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--remove] [--dry-run] [PORT]

  --remove    Delete the QuicFuscate fast-path rule for PORT
  --dry-run   Print the iptables commands without executing them
  PORT        UDP port in ${MIN_PORT}..${MAX_PORT} (default: ${DEFAULT_PORT})
USAGE
}

while (($#)); do
  case "$1" in
    --remove) MODE="remove";;
    --dry-run) DRY_RUN=1;;
    -h|--help) usage; exit 0;;
    -*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2;;
    *)
      if [[ -n "$PORT" ]]; then
        echo "ERROR: unexpected extra argument: $1" >&2
        exit 2
      fi
      PORT="$1"
      ;;
  esac
  shift
done

PORT="${PORT:-$DEFAULT_PORT}"

# Validate before any mutation. A non-numeric or out-of-policy port previously reached
# iptables directly.
if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
  echo "ERROR: port must be a number, got: ${PORT}" >&2
  exit 2
fi
if ((PORT < MIN_PORT || PORT > MAX_PORT)); then
  echo "ERROR: port ${PORT} is outside the supported range ${MIN_PORT}..${MAX_PORT}." >&2
  echo "       System ports are refused: a top-of-chain ACCEPT there would bypass" >&2
  echo "       every preceding policy rule for a service QuicFuscate does not own." >&2
  exit 2
fi

run() {
  if ((DRY_RUN)); then
    printf 'dry-run:'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

if ((DRY_RUN == 0)); then
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (use sudo)." >&2
    exit 1
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    echo "ERROR: iptables is not available on this host." >&2
    exit 1
  fi
  # Without the comment module the rule cannot carry its owner marker, and an
  # unmarked rule is one this script could later delete from someone else or fail to
  # clean up. Refuse rather than silently create an unowned rule.
  if ! iptables -m comment --help >/dev/null 2>&1; then
    echo "ERROR: iptables lacks the 'comment' match; rule ownership cannot be recorded." >&2
    exit 1
  fi
fi

# The full match, including the owner comment. Every insert and every delete uses
# exactly this, so the script can only ever remove what it created.
rule_spec() {
  printf '%s\n' -p udp --dport "$PORT" -m comment --comment "$RULE_COMMENT" -j ACCEPT
}

# Built with a read loop rather than `mapfile`, which macOS Bash 3.2 does not provide.
RULE_SPEC=()
while IFS= read -r spec_field; do
  RULE_SPEC+=("$spec_field")
done < <(rule_spec)

delete_owned_rules() {
  local removed=0
  while run iptables -C INPUT "${RULE_SPEC[@]}" 2>/dev/null; do
    run iptables -D INPUT "${RULE_SPEC[@]}"
    removed=$((removed + 1))
    # In dry-run the check above always succeeds, so stop after showing one delete.
    ((DRY_RUN)) && break
  done
  echo "$removed"
}

if [[ "$MODE" == "remove" ]]; then
  echo "Removing ${RULE_COMMENT} rule for UDP port ${PORT}..."
  count="$(delete_owned_rules)"
  echo "Removed ${count} owned rule(s). Rules created by anything else were left untouched."
  exit 0
fi

echo "Inserting ${RULE_COMMENT} rule for UDP port ${PORT}..."
# Remove our own stale copies first, then insert at position 1 so the rule precedes
# distro or Tailscale chains that may have been prepended since the last run.
delete_owned_rules >/dev/null
run iptables -I INPUT 1 "${RULE_SPEC[@]}"

echo "Rule inserted. Verify with:"
echo "  iptables -L INPUT -n --line-numbers | grep ${RULE_COMMENT}"
echo ""
echo "Expected: 15% nft_do_chain overhead eliminated from UDP fast path."
