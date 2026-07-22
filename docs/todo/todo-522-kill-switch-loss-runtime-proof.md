---
id: TODO-522
title: Close kill-switch automatic-loss handling and privileged runtime proof
severity: CRITICAL
phase: S
priority: P0
status: DONE
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
- [x] Execute privileged Linux and available native platform proofs.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-429 reconciliation. No product code changed during classification.
- Execution started on 2026-07-22 after TODO-547 closure. Initial source proof found four adjacent correctness gaps: standalone remote closure falls through clean firewall removal; iptables IPv6 application is best-effort; nftables matches `iifname` instead of `oifname` for loopback in the output hook; and ordinary iptables cleanup leaves the owned OUTPUT jump and chains installed.
- The canonical contract is now explicit: the embedded client runtime owns one 50 ms watchdog; the standalone Tokio loop owns its equivalent cadence without a second task. Both drive the same typed firewall states: blocked, endpoint-only connecting, VPN/DNS-connected, and disabled. Unexpected remote closure, socket failure, or heartbeat timeout reapplies block-only rules and leaves them installed across process exit; only explicit signal/engine stop or operator stale cleanup removes owned rules.
- `VpnFirewallPolicy` accepts a primary socket address, optional opposite-family server address, validated TUN name, and up to eight deduplicated VPN DNS addresses. Connected rules permit the exact UDP server endpoint, permit port 53 only to selected resolvers through the TUN, reject every other TCP/UDP port-53 destination before the general TUN allow, and cover IPv4 plus IPv6.
- The privileged process gate `scripts/tests/tun-e2e-killswitch-netns.sh` exercises real TLS/TUN establishment, nftables kernel state, VPN DNS, direct DNS and IPv6 capture, server-kill timing, retained rules after process loss, explicit stale cleanup, and SIGTERM cleanup. Local `bash -n` and ShellCheck pass; exact final artifact evidence is recorded below.
- Local full evidence after implementation: workspace all-target tests with `rust-tests` pass 1,720 library tests plus every integration, binary, and example target; workspace all-target check, strict Clippy, `cargo fmt --check`, `git diff --check`, Bash syntax, ShellCheck, TODO consistency (193 files, zero violations), and runtime guardrails (zero critical findings, zero warnings) pass. The final watchdog review also proves that `heartbeat_timeout_ms=0` disables only the inactivity deadline while preserving automatic remote-close detection.
- Local macOS PF access is unavailable: the native stale-cleanup test reaches `pfctl` but receives `/dev/pf: Permission denied`. No privileged state mutation was attempted; the support claim remains conditional on a managed PF anchor until native privileged proof exists.
- Commit `2735a23` passes CI `29921238645`, Clippy Matrix `29921238690`, native Windows core check/test/Clippy, and the ARM64 release-bundle job. The exact ARM64 bundle SHA-256 is `d41764e90d9cc6d9abd2812b0c17f35679c2d4a1dcdbd4ed86ace90dc40a7abf`; its binary SHA-256 is `c285dbcbb53fc6355aec182f99a7f5ec4a409bf93af1874cd4ae8556b6a92e60`.
- Privileged Omega run 9 passes against that binary: selected VPN DNS returns a real response; direct underlay DNS and IPv6 attempts fail with zero matching packets captured; a silent `SIGSTOP` server drives block-only nftables state in 15,005 ms for a 15,000 ms configured timeout; endpoint and TUN allowances are absent; rules persist after client exit; explicit stale cleanup removes them; and a separate SIGTERM lifecycle removes them cleanly. Early diagnostic runs exposed and fixed only harness defects: missing explicit namespace TUN address activation, a timeout shorter than the leak checks, zombie process detection, and `SIGKILL` exercising remote-close instead of inactivity timeout.
- Windows activation now returns `NotSupported` because the previous broad `netsh` block rules override narrower allow rules and cannot provide the claimed policy. Native production replacement remains in TODO-528. The macOS managed PF anchor lifecycle is isolated in TODO-548. The remaining configured backend and iptables fallback matrix stays in TODO-530.
- Commit `a0e9bba` has exact privileged Omega proof against ARM64 bundle SHA-256 `616578a00507006319dceda9dc939ca3a0721da95fe9b44ab1e606897ef10550`, binary SHA-256 `c285dbcbb53fc6355aec182f99a7f5ec4a409bf93af1874cd4ae8556b6a92e60`, and harness SHA-256 `82367fc3c4fa2eab908bd4ef3c5edbfa350af6eb2a477986132d25b664782e8d`: the isolated `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-a0e9bba-killswitch` run passes with a measured 15,000 ms unexpected-loss transition and the complete connected, leak, retained-state, stale-cleanup, and SIGTERM-cleanup matrix. Clippy Matrix `29922849814` is green. CI `29922847968` instead exposed an adjacent AVX-512 VBMI2 GF16 corruption defect on its native Windows host; TODO-547 records the root cause and corrective regression required before closure.
- Final corrective commit `a10cdb5ea852b8000f12e09d4a19bb7782fb10b0` passes local workspace/all-target `rust-tests` with 1,720 library tests plus every integration, binary, and example target, strict Clippy, formatting, TODO consistency, and runtime guardrails. GitHub CI `29924295737` is green, including native Windows core check/test/Clippy job `88937360219` on the previously failing VBMI2 path; Clippy Matrix `29924295741` and complete Release Build `29924295634` are green.
- The exact final ARM64 server bundle SHA-256 is `171871a1cedff433bd15d32a702ed677126c6bc94cda40e8c8478eba325f4564`; its binary SHA-256 is `c285dbcbb53fc6355aec182f99a7f5ec4a409bf93af1874cd4ae8556b6a92e60`, and the harness SHA-256 is `82367fc3c4fa2eab908bd4ef3c5edbfa350af6eb2a477986132d25b664782e8d`. The isolated `/home/ubuntu/SOFTWARE/QuicFuscate/runtime-a10cdb5-killswitch` Omega run passes selected VPN DNS, zero direct DNS/IPv6 capture, block-only retention, stale cleanup, and SIGTERM cleanup with a measured 15,026 ms unexpected-loss transition against the 15,100 ms limit. Historical runtimes were not modified.

## Deviations

None.
