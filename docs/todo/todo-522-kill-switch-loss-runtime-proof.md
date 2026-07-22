---
id: TODO-522
title: Close kill-switch automatic-loss handling and privileged runtime proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-429, TODO-521]
---

# TODO-522: Close Kill-Switch Automatic-Loss Handling and Privileged Runtime Proof

## Why

TODO-521 confirmed that the kill-switch backends and explicit connect/disconnect hooks exist, but `QuicFuscateEngine::check_heartbeat()` has no non-test caller. The standalone client also exits through clean disable after remote closure, so current evidence does not prove that unexpected loss enters and retains the fail-closed firewall state. Privileged Linux, macOS, and Windows state assertions from TODO-429 were never retained.

## Acceptance

- Wire automatic heartbeat/remote-close detection into the owning runtime at a measured cadence that activates the blocked ruleset within 100 ms after the configured timeout.
- Distinguish explicit clean shutdown, which removes owned rules, from unexpected tunnel loss, which retains fail-closed blocking until recovery or explicit operator cleanup.
- Extend the connected-state contract to accept optional server IPv6 and VPN DNS addresses, allow only the selected VPN resolver on port 53, and block direct DNS to every other resolver across IPv4 and IPv6.
- Prove Linux block, connected exception, disconnected block, clean cleanup, and stale cleanup against real kernel firewall state on Omega.
- Prove IPv6 blocking plus VPN-DNS-only behavior with real DNS queries and packet capture, not command-string assertions.
- Prove the macOS pf anchor lifecycle locally when privilege access permits; otherwise narrow the support claim and record the exact blocker.
- Prove Windows command lifecycle on a native privileged runner or narrow the support claim; native compilation alone is not runtime proof.
- Add failable process-level regression coverage for automatic loss and signal cleanup.
- Pass full local Rust gates, relevant native CI, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Identify the canonical owner and lifecycle contract for engine and standalone client loss detection.
- [ ] Implement automatic fail-closed transitions without duplicate watchdogs.
- [ ] Add process and platform-boundary tests.
- [ ] Execute privileged Linux and available native platform proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-429 reconciliation. No product code changed during classification.

## Deviations

None.
