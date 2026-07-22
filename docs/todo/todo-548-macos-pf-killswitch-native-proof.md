---
id: TODO-548
title: Install and prove the managed macOS PF kill-switch anchor
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-522, TODO-521]
---

# TODO-548: Install and Prove the Managed macOS PF Kill-Switch Anchor

## Why

TODO-522 narrowed macOS support after local `pfctl` access returned `/dev/pf: Permission denied`. The runtime now refuses to claim protection unless the main PF ruleset exposes `com.quicfuscate.killswitch` or a matching wildcard anchor, but no installer owns that reference and no privileged packet proof exists.

## Acceptance

- Define one reversible, idempotent owner for installing and removing the QuicFuscate PF anchor reference without replacing unrelated system or user PF rules.
- Prove block-only, endpoint-only, connected TUN, selected DNS, IPv4, IPv6, clean cleanup, retained unexpected-loss state, and stale cleanup with real privileged packet outcomes.
- Preserve pre-existing PF enablement and unrelated anchors across install, restart, crash, cleanup, and uninstall.
- Fail closed with an exact diagnostic when the anchor is absent, inaccessible, or modified by another owner.
- Pass full local Rust gates, native macOS CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Audit current macOS PF ownership and installer boundaries.
- [ ] Implement reversible managed-anchor lifecycle without replacing the main ruleset.
- [ ] Add privileged native packet and coexistence tests.
- [ ] Execute install, restart, crash, cleanup, and uninstall proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from the narrowed TODO-522 macOS support boundary.

## Deviations

None.
