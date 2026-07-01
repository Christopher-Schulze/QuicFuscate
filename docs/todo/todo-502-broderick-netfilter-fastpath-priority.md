---
id: TODO-502
title: Broderick netfilter fastpath priority
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-418, TODO-473, TODO-474]
---

# TODO-502: Broderick Netfilter Fastpath Priority

## Context

Broderick profiling showed the UDP fast path is dominated by kernel send/receive
work, with `nft_do_chain` previously accounting for a material share of packet
cost. The existing `scripts/install/setup-netfilter-fastpath.sh` script was
intended to insert an UDP/4433 ACCEPT rule at the top of `INPUT`, but it only
checked whether the rule existed anywhere. If another service, such as
Tailscale, later prepended its own chain, rerunning the script left the
QuicFuscate rule below that chain instead of moving it back to position 1.

On Broderick, the live state had `ts-input` at INPUT line 1 and the QuicFuscate
UDP/4433 ACCEPT rule at line 2. That still protects correctness, but it does not
fully honor the profiling-driven fastpath intent: QuicFuscate UDP should bypass
the extra chain as early as possible.

## Desired Outcome

- Keep the script idempotent.
- Ensure exactly one UDP/4433 ACCEPT rule remains after repeated runs.
- Ensure the rule is inserted at INPUT position 1, ahead of distro or Tailscale
  chains that may have been prepended after a previous run.
- Preserve the existing remove mode.
- Avoid UI, frontend, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Added `delete_existing_fastpath_rules()` to remove all stale copies of the
  matching UDP/port ACCEPT rule.
- Updated normal insertion to delete stale copies first, then insert the rule at
  INPUT position 1.
- Updated remove mode to delete all matching stale copies instead of only one.
- Applied the fixed script on Broderick for UDP port `4433`.

## Broderick Evidence

After two consecutive script runs:

| Check | Result |
|-------|--------|
| INPUT line 1 | `ACCEPT udp dpt:4433` |
| INPUT line 2 | `ts-input` |
| UDP/4433 ACCEPT rule count | `1` |

This proves the fastpath setup is idempotent and actually restores the
profiling-intended rule priority on the server.

## Verification

- Local: `bash -n scripts/install/setup-netfilter-fastpath.sh` pass.
- Broderick: `bash -n scripts/install/setup-netfilter-fastpath.sh` pass.
- Broderick: `scripts/install/setup-netfilter-fastpath.sh 4433` pass.
- Broderick: repeated script execution leaves exactly one UDP/4433 ACCEPT rule
  at INPUT line 1.

## Notes

The broad Criterion probe before this fix showed no new Rust-level regression
in Connection, Stealth padding, StealthBrain, or FEC. The remaining server
fastpath evidence points at kernel/netfilter behavior, so this task fixes the
server-side operational path that was drifting away from the measured baseline.
