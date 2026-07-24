---
id: TODO-548
title: Install and prove the managed macOS PF kill-switch anchor
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-522, TODO-530, TODO-542]
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

## Completion Gates

- Ownership gate: install, load, inspect, update, and remove operations target one managed anchor and never replace or flush the main PF ruleset or unrelated anchors.
- Packet gate: privileged native evidence proves block-only, endpoint-only, connected TUN, selected DNS, IPv4, IPv6, unexpected-loss retention, and stale-startup cleanup through real outcomes.
- Coexistence gate: pre-existing PF enablement and unrelated rules survive install, restart, crash, cleanup, uninstall, absent-anchor, inaccessible-anchor, and foreign-modification cases.
- Release gate: full Rust gates, native macOS CI, signed exact-artifact proof, SHA-256, final PF/residue inspection, protected UI diff, and owning-doc updates all pass.

## Sub-Tasks

- [ ] Audit current macOS PF ownership and installer boundaries.
- [ ] Implement reversible managed-anchor lifecycle without replacing the main ruleset.
- [ ] Add privileged native packet and coexistence tests.
- [ ] Execute install, restart, crash, cleanup, and uninstall proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from the narrowed TODO-522 macOS support boundary.
- Primary surfaces: `src/implementations/client/killswitch.rs`, `src/implementations/client/platform/macos.rs`, `src/interface.rs`, `scripts/install/`, and the native kill-switch test boundary.
- Scope lock: own only a named QuicFuscate anchor reference and its lifecycle. Never replace the main PF ruleset, disable PF that QuicFuscate did not enable, weaken the absent-anchor fail-closed behavior, or infer protection from command success without packet proof.
- Evidence bundle: retain original and final PF state, anchor hashes, enablement ownership, real IPv4/IPv6/DNS/endpoint/TUN packet outcomes, crash/restart/uninstall transitions, foreign-anchor fingerprints, signed artifact SHA-256, and final residue inspection.

## Deviations

None.
