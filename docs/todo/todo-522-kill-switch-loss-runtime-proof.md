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

- [x] Identify the canonical owner and lifecycle contract for engine and standalone client loss detection.
- [x] Implement automatic fail-closed transitions without duplicate watchdogs.
- [x] Add process and platform-boundary tests.
- [~] Execute privileged Linux and available native platform proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-429 reconciliation. No product code changed during classification.
- Execution started on 2026-07-22 after TODO-547 closure. Initial source proof found four adjacent correctness gaps: standalone remote closure falls through clean firewall removal; iptables IPv6 application is best-effort; nftables matches `iifname` instead of `oifname` for loopback in the output hook; and ordinary iptables cleanup leaves the owned OUTPUT jump and chains installed.
- The canonical contract is now explicit: the embedded client runtime owns one 50 ms watchdog; the standalone Tokio loop owns its equivalent cadence without a second task. Both drive the same typed firewall states: blocked, endpoint-only connecting, VPN/DNS-connected, and disabled. Unexpected remote closure, socket failure, or heartbeat timeout reapplies block-only rules and leaves them installed across process exit; only explicit signal/engine stop or operator stale cleanup removes owned rules.
- `VpnFirewallPolicy` accepts a primary socket address, optional opposite-family server address, validated TUN name, and up to eight deduplicated VPN DNS addresses. Connected rules permit the exact UDP server endpoint, permit port 53 only to selected resolvers through the TUN, reject every other TCP/UDP port-53 destination before the general TUN allow, and cover IPv4 plus IPv6.
- The privileged process gate `scripts/tests/tun-e2e-killswitch-netns.sh` exercises real TLS/TUN establishment, nftables kernel state, VPN DNS, direct DNS and IPv6 capture, server-kill timing, retained rules after process loss, explicit stale cleanup, and SIGTERM cleanup. Local `bash -n` and ShellCheck pass; execution awaits the exact native Linux artifact.
- Local full evidence after implementation: workspace all-target tests with `rust-tests` pass 1,720 library tests plus every integration, binary, and example target; workspace all-target check, strict Clippy, `cargo fmt --check`, `git diff --check`, Bash syntax, ShellCheck, TODO consistency (193 files, zero violations), and runtime guardrails (zero critical findings, zero warnings) pass. The final watchdog review also proves that `heartbeat_timeout_ms=0` disables only the inactivity deadline while preserving automatic remote-close detection.
- Local macOS PF access is unavailable: the native stale-cleanup test reaches `pfctl` but receives `/dev/pf: Permission denied`. No privileged state mutation was attempted; the support claim remains conditional on a managed PF anchor until native privileged proof exists.

## Deviations

None.
