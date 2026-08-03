#!/usr/bin/env bash
# Read-only macOS PF activation proof for the QuicFuscate kill-switch anchor.
set -euo pipefail

ANCHOR="${PF_ANCHOR:-com.quicfuscate.killswitch}"

usage() {
  cat <<'USAGE'
Usage: macos-pf-anchor-proof.sh [--anchor NAME]

Read-only privileged proof that:
  1) pf is enabled;
  2) the main ruleset references the requested QuicFuscate anchor; and
  3) the anchor exposes a block-out policy.

The script never enables pf, loads rules, or flushes an anchor.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --anchor)
      ANCHOR="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS PF proof requires Darwin" >&2
  exit 2
fi
if ! command -v pfctl >/dev/null 2>&1; then
  echo "missing required command: pfctl" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "macOS PF proof requires root to inspect the active ruleset" >&2
  exit 2
fi
if [[ -z "$ANCHOR" || ! "$ANCHOR" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "invalid PF anchor name: $ANCHOR" >&2
  exit 2
fi

PF_INFO="$(pfctl -s info)" || {
  echo "pfctl -s info failed" >&2
  exit 1
}
grep -q 'Status: Enabled' <<<"$PF_INFO" || {
  echo "pf is not enabled" >&2
  exit 1
}

MAIN_RULES="$(pfctl -sr)" || {
  echo "pfctl -sr failed" >&2
  exit 1
}
if ! awk -v expected="\"$ANCHOR\"" '
  $1 == "anchor" && ($2 == expected || $2 == "\"com.quicfuscate/*\"") { found = 1 }
  END { exit(found ? 0 : 1) }
' <<<"$MAIN_RULES"; then
  echo "main PF ruleset does not reference anchor: $ANCHOR" >&2
  exit 1
fi

ANCHOR_RULES="$(pfctl -a "$ANCHOR" -sr)" || {
  echo "pfctl -a $ANCHOR -sr failed" >&2
  exit 1
}
grep -Eq '[^[:space:]]' <<<"$ANCHOR_RULES" || {
  echo "PF anchor has no active rules: $ANCHOR" >&2
  exit 1
}
grep -Eq '(^|[[:space:]])block[[:space:]]+out[[:space:]]+all([[:space:]]|$)' <<<"$ANCHOR_RULES" || {
  echo "PF anchor lacks the expected block-out rule: $ANCHOR" >&2
  exit 1
}

echo "PASS: pf enabled, main ruleset references $ANCHOR, and the active anchor blocks outbound traffic"
