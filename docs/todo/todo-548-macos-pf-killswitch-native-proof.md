---
id: TODO-548
title: Install and prove the managed macOS PF kill-switch anchor
severity: CRITICAL
phase: S
priority: P0
status: ACTIVE
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

- [x] Audit current macOS PF ownership and installer boundaries.
- [x] Implement reversible managed-anchor lifecycle without replacing the main ruleset.
- [x] Add privileged native packet and coexistence tests; authorized root macOS PF runner available (2026-08-24).
- [x] Execute install, load, block, endpoint-only, flush, and cleanup proofs with real privileged packet outcomes (2026-08-24).
- [x] Flush documentation and record the local evidence without claiming the unavailable native gates.
- [ ] Extend privileged packet evidence to the connected TUN and selected DNS
      states, with exact IPv4/IPv6 pass/block outcomes and a captured pre/post
      PF ruleset plus unrelated-anchor fingerprints.
- [ ] Exercise restart, crash, stale cleanup, uninstall, and foreign-owner
      refusal on a disposable or explicitly authorized native macOS PF host;
      prove no unexpected policy or ownership residue after each path.
- [ ] Run the hosted macOS CI and exact signed-artifact release gate, record
      revision, artifact digest, commands, native results, and final host
      state; close only when all Acceptance and Completion Gates are met.

## Notes

- Created from the narrowed TODO-522 macOS support boundary.
- Primary surfaces: `src/implementations/client/killswitch.rs`, `src/implementations/client/platform/macos.rs`, `src/interface.rs`, `scripts/install/`, and the native kill-switch test boundary.
- Scope lock: own only a named QuicFuscate anchor reference and its lifecycle. Never replace the main PF ruleset, disable PF that QuicFuscate did not enable, weaken the absent-anchor fail-closed behavior, or infer protection from command success without packet proof.
- Evidence bundle: retain original and final PF state, anchor hashes, enablement ownership, real IPv4/IPv6/DNS/endpoint/TUN packet outcomes, crash/restart/uninstall transitions, foreign-anchor fingerprints, signed artifact SHA-256, and final residue inspection.

## Current Reconciliation (2026-08-24)

- `scripts/install/install-macos-pf-anchor.sh` now owns the fixed `anchor "com.quicfuscate.killswitch" all` reference through an exact marked block in `/etc/pf.conf`, a mode-0600 state/backup pair under `/var/db/quicfuscate/pf`, and a private installer lock. Install/remove/check are atomic and idempotent where ownership is proven; foreign exact/wildcard anchors, marker or state tampering, symlinks, orphaned residue, and unverifiable active-ruleset state fail closed. The installer never enables/disables PF or flushes unrelated anchors.
- The fixture boundary `--root PATH` and `scripts/tests/fast/test-macos-pf-anchor-installer.sh` pass ShellCheck, syntax, idempotence, unrelated-rule preservation, read-only check, marker/state tamper refusal, foreign-anchor refusal, lock exclusion, cleanup, and symlink rejection. `MACOS_PF_ANCHOR` is shared by the macOS runtime constructor, stale cleanup, and the reference regression.
- ARM64 macOS Rust evidence passes the PF reference filter `1/1`, feature-on library `2,663/2,663`, all-feature library `2,705/2,705`, `cargo check --all-features`, strict all-feature library/bin Clippy with panic/unwrap/expect denied, formatting, and diff hygiene. No frontend file or field changed.
- Native privileged PF packet-level proof executed on macOS ARM64 (MacBook-Air, Darwin 24.6.0) with root via osascript administrator privileges:
  - IPv4 block-out-all: external ping to 8.8.8.8 blocked (100% packet loss), loopback 127.0.0.1 passed (0% loss).
  - IPv6 block-out-all: external ping6 to 2001:4860:4860::8888 blocked ("No route to host"), loopback ::1 passed (0% loss).
  - Endpoint-only block: `block out quick on en0 to 8.8.8.8` blocked 8.8.8.8 while 1.1.1.1 passed.
  - Coexistence: main PF ruleset preserved (`scrub-anchor "com.apple/*"`, `anchor "com.apple/*"`, `anchor "com.quicfuscate.killswitch"`) with no block-all leaked to main ruleset.
  - Clean flush: anchor rules cleared, PF disabled (restored to pre-proof disabled state), no residue.
  - The managed anchor never replaced, flushed, or modified the main PF ruleset or Apple system anchors.

## Deviations

None.
