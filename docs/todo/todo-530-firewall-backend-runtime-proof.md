---
id: TODO-530
title: Wire firewall backend override and privileged nftables proof
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-22
depends_on: [TODO-444, TODO-522, TODO-523, TODO-521]
---

# TODO-530: Wire Firewall Backend Override and Privileged nftables Proof

## Why

Auto-detection, nftables kill-switch/routing transactions, iptables fallback, and rule-parity units exist. The typed `FirewallConfig` override is parsed but ignored by runtime constructors, and no privileged proof establishes live nftables state, fallback state, packet flow, fail-closed behavior, or cleanup.

## Acceptance

- Thread one resolved backend selection from validated `FirewallConfig` into client kill switch and server routing; no subsystem may independently re-detect after startup.
- Explicit nftables must fail closed when unavailable, explicit iptables must never select nftables, and auto must log exact probe result plus selection.
- Apply and remove only dedicated QuicFuscate nftables tables atomically and idempotently across clean shutdown and stale startup cleanup.
- Prove on Omega the unified nftables NAT/forwarding table, kill-switch blocked/connected states, real TUN traffic, IPv4/IPv6 behavior, and exact cleanup.
- Prove iptables fallback on a controlled no-nft environment with real state and traffic rather than mocked process output.
- Coordinate TODO-522 kill-switch and TODO-523 isolation rules so backend ownership never creates parallel or contradictory policies.
- Pass full local Rust gates, native CI, Omega proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [ ] Define the single backend-selection owner and configuration error contract.
- [ ] Wire selection through kill-switch and routing constructors.
- [ ] Add deterministic negative, fallback, lifecycle, and parity tests.
- [ ] Execute privileged nftables and iptables traffic proofs.
- [ ] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-444 reconciliation. The canonical routing table is `inet quicfuscate_rt`.
- TODO-522 now provides privileged Omega proof for automatic nftables kill-switch selection: exact endpoint-only and connected rules, selected VPN DNS, direct DNS/IPv6 blocking with zero captured leaks, block-only timeout transition, retained post-exit rules, stale cleanup, and SIGTERM cleanup. This task remains open for the single configured backend owner, unified routing-table proof, explicit nftables failure behavior, and real iptables fallback/atomicity proof.

## Deviations

None.
