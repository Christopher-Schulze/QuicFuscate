#!/usr/bin/env bash
# Netfilter fast-path rule for QuicFuscate UDP traffic.
#
# The profiling baseline (docs/profiling/baseline-2026-07.md) shows 15% CPU
# overhead from nft_do_chain evaluating iptables rules for every UDP packet.
# This script inserts a fast-path ACCEPT rule at the top of INPUT for the
# QuicFuscate UDP port, bypassing the full iptables rule chain.
#
# Usage:
#   sudo ./setup-netfilter-fastpath.sh [PORT]
#   PORT defaults to 4433 (from config/server-linux.default.toml)
#
# To remove:
#   sudo ./setup-netfilter-fastpath.sh --remove [PORT]

set -euo pipefail

PORT="${1:-4433}"

delete_existing_fastpath_rules() {
  local port="$1"
  while iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do
    iptables -D INPUT -p udp --dport "$port" -j ACCEPT
  done
}

if [[ "$PORT" == "--remove" ]]; then
  PORT="${2:-4433}"
  echo "Removing netfilter fast-path rule for UDP port $PORT..."
  delete_existing_fastpath_rules "$PORT"
  echo "Done."
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Must run as root (use sudo)." >&2
  exit 1
fi

echo "Inserting netfilter fast-path rule for UDP port $PORT..."
# Remove any stale lower-priority copy first, then insert at position 1 (top of
# INPUT chain) to bypass all subsequent rules, including distro/Tailscale chains
# that may be prepended after a previous run. This eliminates the measured
# nft_do_chain overhead instead of merely adding a duplicate lower in the chain.
delete_existing_fastpath_rules "$PORT"
iptables -I INPUT 1 -p udp --dport "$PORT" -j ACCEPT

echo "Rule inserted. Verify with:"
echo "  iptables -L INPUT -n --line-numbers | head -5"
echo ""
echo "Expected: 15% nft_do_chain overhead eliminated from UDP fast path."
